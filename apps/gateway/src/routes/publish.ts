import type { FastifyReply, FastifyRequest } from "fastify";
import semver from "semver";
import type { AppContext } from "../context.js";
import { assertPackageAccess, authenticatePublisher } from "../auth.js";
import {
  getReleaseByPackageVersion,
  insertRelease,
  insertEvent,
  isUniqueViolation,
} from "../releases.js";
import {
  hasInstallableRelease,
  isInstallable,
} from "../registry-view.js";
import {
  isScopedName,
  normalizePackageName,
  validatePackageName,
} from "../npm/names.js";
import {
  DistTagError,
  deleteDistTag as deleteDistTagRecord,
  setDistTag as setDistTagRecord,
} from "../serving.js";
import {
  IngestionError,
  auditIngestionRejection,
} from "../ingestion.js";
import { getCurrentAudit } from "../releases.js";
import type { ReleaseStatus } from "@veripack/shared";
import { parsePublishPayload, PayloadError } from "../npm/payload.js";
import { buildPayloadKey, buildTarballKey } from "../storage.js";
import { dispatchAuditOutboxOnce } from "../audit/outbox.js";

interface DistTagPath {
  packageName: string;
  tag: string;
}

function parseDistTagPath(path: string): DistTagPath | null {
  const marker = "/-/dist-tags/";
  const index = path.indexOf(marker);
  if (index <= 0) return null;
  const packageName = path.slice(0, index);
  const tag = path.slice(index + marker.length);
  if (!tag || tag.includes("/")) return null;
  return { packageName, tag };
}

function readDistTagVersion(body: unknown): string | null {
  const value =
    typeof body === "string"
      ? body
      : typeof body === "object" && body !== null && "version" in body
        ? (body as { version?: unknown }).version
        : null;
  if (typeof value !== "string") return null;
  const version = value.trim();
  return semver.valid(version) ? version : null;
}

function validDistTag(tag: string): boolean {
  return tag.length <= 128 && /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(tag);
}

export async function distTagHandler(
  request: FastifyRequest,
  reply: FastifyReply,
  context: AppContext,
): Promise<void> {
  const rawPath = String(
    (request.params as Record<string, string | undefined>)["*"] ?? "",
  );
  const path = normalizePackageName(rawPath);
  const parsed = parseDistTagPath(path);
  if (!parsed || !validDistTag(parsed.tag)) {
    reply.code(405).send({ error: "Only validated package dist-tag mutations are supported." });
    return;
  }

  const publisher = await authenticatePublisher(request, context.config);
  const nameError = validatePackageName(parsed.packageName);
  if (nameError) {
    throw new PayloadError(nameError);
  }
  assertPackageAccess(publisher, parsed.packageName, "publish");

  if (request.method === "DELETE") {
    const owned = await hasInstallableRelease(
      context.pool,
      context.config.ORG_ID,
      parsed.packageName,
    );
    if (!owned) {
      reply.code(409).send({
        error: "Public upstream package dist-tags are read-only through Veripack.",
      });
      return;
    }
    await deleteDistTagRecord(context.pool, {
      orgId: context.config.ORG_ID,
      packageName: parsed.packageName,
      tag: parsed.tag,
      updatedBy: publisher.username,
      source: "publisher",
    });
    let mirrored = true;
    try {
      await context.verdaccio.deleteDistTag(parsed.packageName, parsed.tag);
    } catch (error) {
      mirrored = false;
      request.log.error(
        { err: error, packageName: parsed.packageName, tag: parsed.tag },
        "dist-tag mirror failed; database remains authoritative",
      );
      await insertEvent(context.pool, {
        orgId: context.config.ORG_ID,
        actor: publisher.username,
        action: "package.dist_tag_mirror_failed",
        metadata: { packageName: parsed.packageName, tag: parsed.tag },
      }).catch(() => undefined);
    }
    reply.send({ ok: true, mirrored });
    return;
  }

  if (parsed.tag === "latest") {
    reply.code(403).send({
      error: "The latest tag is computed by Veripack and cannot be set directly.",
    });
    return;
  }

  const version = readDistTagVersion(request.body);
  if (!version) {
    throw new PayloadError("A dist-tag update requires a valid semver version.");
  }
  const release = await getReleaseByPackageVersion(
    context.pool,
    context.config.ORG_ID,
    parsed.packageName,
    version,
  );
  if (!release || !isInstallable(release)) {
    reply.code(409).send({
      error: `${parsed.packageName}@${version} is not an installable Veripack release.`,
    });
    return;
  }

  try {
    await setDistTagRecord(context.pool, {
      orgId: context.config.ORG_ID,
      packageName: parsed.packageName,
      tag: parsed.tag,
      version,
      updatedBy: publisher.username,
      source: "publisher",
    });
  } catch (error) {
    if (error instanceof DistTagError) {
      reply.code(409).send({ error: error.message });
      return;
    }
    throw error;
  }
  let mirrored = true;
  try {
    await context.verdaccio.setDistTag(parsed.packageName, parsed.tag, version);
  } catch (error) {
    mirrored = false;
    request.log.error(
      { err: error, packageName: parsed.packageName, tag: parsed.tag },
      "dist-tag mirror failed; database remains authoritative",
    );
    await insertEvent(context.pool, {
      orgId: context.config.ORG_ID,
      actor: publisher.username,
      action: "package.dist_tag_mirror_failed",
      metadata: { packageName: parsed.packageName, tag: parsed.tag, version },
    }).catch(() => undefined);
  }
  reply.send({ ok: true, package: parsed.packageName, tag: parsed.tag, version, mirrored });
}

export async function publishHandler(
  request: FastifyRequest,
  reply: FastifyReply,
  context: AppContext,
): Promise<void> {
  const rawPath = String(
    (request.params as Record<string, string | undefined>)["*"] ?? "",
  );
  const path = normalizePackageName(rawPath);

  const distTag = parseDistTagPath(path);
  if (distTag) {
    await distTagHandler(request, reply, context);
    return;
  }

  // Do not forward arbitrary npm control-plane PUTs. Registry credentials are
  // Veripack tokens; Verdaccio user-management endpoints are not public.
  if (path.startsWith("-/")) {
    await authenticatePublisher(request, context.config);
    reply.code(405).send({
      error: "This npm control-plane mutation is not supported by Veripack.",
    });
    return;
  }

  const publisher = await authenticatePublisher(request, context.config);

  const parsed = parsePublishPayload(request.body);

  if (parsed.packageName !== path) {
    throw new PayloadError(
      `URL package name "${path}" does not match payload name "${parsed.packageName}".`,
    );
  }

  const nameError = validatePackageName(parsed.packageName);
  if (nameError) {
    throw new PayloadError(nameError);
  }

  assertPackageAccess(publisher, parsed.packageName, "publish");

  if (
    !isScopedName(parsed.packageName) &&
    !context.config.ALLOW_UNSCOPED_NAMES
  ) {
    throw new PayloadError(
      "Unscoped private names require an admin-approved claim. Publish as @scope/name or set ALLOW_UNSCOPED_NAMES=true for local testing.",
    );
  }

  if (!semver.valid(parsed.version)) {
    throw new PayloadError(`"${parsed.version}" is not a valid semver version.`);
  }

  if (!parsed.intent?.trim()) {
    reply.code(400).send({
      error:
        "trust.intent is required for private releases. Add trust.intent to the packed manifest (veripack publish --intent writes it for you).",
    });
    return;
  }

  if (
    parsed.attachmentName.includes("/") ||
    parsed.attachmentName.includes("\\") ||
    !parsed.attachmentName.toLowerCase().endsWith(".tgz")
  ) {
    throw new PayloadError("Invalid tarball attachment name.");
  }

  const existing = await context.pool.query<{
    id: string;
    tarball_digest: string;
    status: ReleaseStatus;
  }>(
    `select id, tarball_digest, status from releases
     where org_id = $1 and package_name = $2 and version = $3`,
    [context.config.ORG_ID, parsed.packageName, parsed.version],
  );

  if (existing.rows.length > 0) {
    const row = existing.rows[0]!;
    if (row.tarball_digest !== parsed.tarballDigest) {
      reply.code(409).send({
        error: `${parsed.packageName}@${parsed.version} already exists with different content.`,
      });
      return;
    }
    // Idempotent republish: the same bytes return the existing release.
    const audit = await getCurrentAudit(context.pool, row.id);
    reply.code(200).send({
      ok: true,
      id: row.id,
      package: parsed.packageName,
      version: parsed.version,
      status: row.status,
      auditId: audit?.id ?? null,
      idempotent: true,
    });
    return;
  }

  const limiter = context.ingestion!;
  let releaseSlot: () => void;
  try {
    if (parsed.tarball.length > limiter.limits.maxTarballBytes) {
      throw new IngestionError(
        `Tarball exceeds the ${limiter.limits.maxTarballBytes} byte ingestion limit.`,
        413,
      );
    }
    releaseSlot = limiter.acquire(publisher.username, parsed.tarball.length);
  } catch (error) {
    if (error instanceof IngestionError) {
      await auditIngestionRejection(context.pool, {
        orgId: context.config.ORG_ID,
        actor: publisher.username,
        packageName: parsed.packageName,
        error,
      });
      if (error.retryAfterSeconds) {
        reply.header("retry-after", String(error.retryAfterSeconds));
      }
      reply.code(error.statusCode).send({ error: error.message });
      return;
    }
    throw error;
  }

  const tarballKey = buildTarballKey(
    context.config.ORG_ID,
    parsed.packageName,
    parsed.version,
    parsed.tarballDigest,
  );
  const payloadKey = buildPayloadKey(
    context.config.ORG_ID,
    parsed.packageName,
    parsed.version,
    parsed.tarballDigest,
  );

  try {
    await Promise.all([
      context.storage.putTarball(tarballKey, parsed.tarball),
      context.storage.putJson(payloadKey, parsed.payload),
    ]);
  } catch (error) {
    await Promise.allSettled([
      context.storage.deleteObject(tarballKey),
      context.storage.deleteObject(payloadKey),
    ]);
    releaseSlot();
    throw error;
  }

  let release;
  try {
    release = await insertRelease(context.pool, {
      orgId: context.config.ORG_ID,
      packageName: parsed.packageName,
      version: parsed.version,
      tarballDigest: parsed.tarballDigest,
      tarballKey,
      tarballFilename: parsed.attachmentName,
      payloadKey,
      integrity: parsed.integrity,
      shasum: parsed.shasum,
      publisher: publisher.username,
      intent: parsed.intent,
      manifest: parsed.manifest as Record<string, unknown>,
      eventMetadata: {
        npmUser: parsed.npmUser,
        intent: parsed.intent,
      },
    });
  } catch (error) {
    if (isUniqueViolation(error)) {
      releaseSlot();
      reply.code(409).send({
        error: `${parsed.packageName}@${parsed.version} is already in the registry.`,
      });
      return;
    }
    await Promise.allSettled([
      context.storage.deleteObject(tarballKey),
      context.storage.deleteObject(payloadKey),
    ]);
    releaseSlot();
    throw error;
  }

  try {
    await dispatchAuditOutboxOnce({
      pool: context.pool,
      boss: context.boss,
      config: context.config,
      logger: {
        info: (obj, message) => request.log.info(obj, message),
        error: (obj, message) => request.log.error(obj, message),
      },
    }, release.id);
  } catch (error) {
    request.log.error(
      { err: error, releaseId: release.id },
      "failed to enqueue audit job",
    );
    request.log.error(
      { err: error, releaseId: release.id },
      "release stored; durable audit outbox will retry queue dispatch",
    );
  }

  request.log.info(
    {
      releaseId: release.id,
      packageName: release.package_name,
      version: release.version,
      digest: release.tarball_digest,
    },
    "release stored as pending",
  );

  releaseSlot();
  reply.code(201).send({
    ok: true,
    id: release.id,
    package: release.package_name,
    version: release.version,
    status: release.status,
    auditId: null,
    message:
      "Release stored and queued for audit. It is not installable until the publish gate approves it.",
  });
}

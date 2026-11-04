import { createHash } from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import semver from "semver";
import { authenticatePublisher, assertPackageAccess } from "../auth.js";
import type { AppContext } from "../context.js";
import { getActivePolicy } from "../policy-store.js";
import { parseAuditPolicy } from "../audit/policy.js";
import { runAudit } from "../audit/run.js";
import { runSandbox } from "../sandbox.js";
import {
  countInstallableReleases,
  getPreviousInstallableRelease,
} from "../registry-view.js";
import { listPackageNames } from "../releases.js";
import {
  validatePublishManifest,
  type NpmVersionManifest,
} from "../npm/payload.js";
import { isScopedName, validatePackageName } from "../npm/names.js";
import {
  IngestionError,
  WorkDeduper,
  auditIngestionRejection,
  decodeBase64Tarball,
} from "../ingestion.js";

const preflightDeduper = new WorkDeduper<
  Awaited<ReturnType<typeof runAudit>>
>();

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function bad(reply: FastifyReply, message: string): void {
  reply.code(400).send({ error: message });
}

export async function registerPreflightRoutes(
  app: FastifyInstance,
  context: AppContext,
): Promise<void> {
  app.post("/-/veripack/preflight", async (request: FastifyRequest, reply) => {
    const publisher = await authenticatePublisher(request, context.config);
    if (!isRecord(request.body)) {
      bad(reply, "Preflight body must be a JSON object.");
      return;
    }
    const body = request.body;
    const packageName = typeof body.packageName === "string" ? body.packageName : "";
    const version = typeof body.version === "string" ? body.version : "";
    const manifest = body.manifest;
    const encoded = typeof body.tarballBase64 === "string" ? body.tarballBase64 : "";
    if (!packageName || !version || !isRecord(manifest) || !encoded) {
      bad(reply, "Preflight requires packageName, version, manifest, and tarballBase64.");
      return;
    }
    const nameError = validatePackageName(packageName);
    if (nameError) {
      bad(reply, nameError);
      return;
    }
    if (!semver.valid(version)) {
      bad(reply, `"${version}" is not a valid semver version.`);
      return;
    }
    if (manifest.name !== packageName || manifest.version !== version) {
      bad(reply, "Manifest name/version must match packageName/version.");
      return;
    }
    const manifestError = validatePublishManifest(manifest);
    if (manifestError) {
      bad(reply, manifestError);
      return;
    }
    if (!isScopedName(packageName) && !context.config.ALLOW_UNSCOPED_NAMES) {
      bad(reply, "Unscoped package names are disabled for this registry.");
      return;
    }
    assertPackageAccess(publisher, packageName, "publish");
    const limiter = context.ingestion!;
    let tarball: Buffer;
    try {
      tarball = decodeBase64Tarball(encoded, limiter.limits.maxTarballBytes);
    } catch (error) {
      if (error instanceof IngestionError) {
        await auditIngestionRejection(context.pool, {
          orgId: context.config.ORG_ID,
          actor: publisher.username,
          packageName,
          error,
        });
        reply.code(error.statusCode).send({ error: error.message });
        return;
      }
      throw error;
    }

    const [previous, releaseCount] = await Promise.all([
      getPreviousInstallableRelease(
        context.pool,
        context.config.ORG_ID,
        packageName,
        new Date(),
      ),
      countInstallableReleases(context.pool, context.config.ORG_ID, packageName),
    ]);
    let previousTarball: Buffer | null = null;
    if (previous) {
      previousTarball = await context.storage
        .getBuffer(previous.tarball_key)
        .catch(() => null);
    }
    const fallback = parseAuditPolicy(
      context.config.AUDIT_POLICY_VERSION,
      context.config.AUDIT_POLICY_JSON,
    );
    const policy = (await getActivePolicy(context.pool, context.config.ORG_ID, fallback)).active;
    const trust = isRecord(manifest.trust) ? manifest.trust : null;
    const intent =
      typeof trust?.intent === "string"
        ? trust.intent
        : typeof manifest.trustIntent === "string"
          ? manifest.trustIntent
          : null;
    if (!intent?.trim()) {
      bad(
        reply,
        "trust.intent is required for private releases. Add trust.intent to the packed manifest (veripack publish --intent writes it for you).",
      );
      return;
    }
    if (body.sandbox === true && context.config.SANDBOX_MODE === "disabled") {
      reply.code(409).send({ error: "Sandbox requested but SANDBOX_MODE is disabled." });
      return;
    }

    let releaseSlot: () => void;
    try {
      releaseSlot = limiter.acquire(publisher.username, tarball.length);
    } catch (error) {
      if (error instanceof IngestionError) {
        await auditIngestionRejection(context.pool, {
          orgId: context.config.ORG_ID,
          actor: publisher.username,
          packageName,
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

    let audited: Awaited<ReturnType<typeof runAudit>>;
    try {
      const dedupeKey = [
        createHash("sha256").update(tarball).digest("hex"),
        context.config.AUDIT_ENGINE_VERSION,
        policy.version,
      ].join(":");
      const existingPackageNames = await listPackageNames(
        context.pool,
        context.config.ORG_ID,
      );
      audited = await limiter.withTimeout(() =>
        preflightDeduper.run(dedupeKey, () =>
          runAudit({
      packageName,
      version,
      publisher: publisher.username,
      manifest: manifest as NpmVersionManifest,
      intent,
      tarball,
      tarballDigest: createHash("sha256").update(tarball).digest("hex"),
      policy,
      previous: previous
        ? {
            version: previous.version,
            publisher: previous.publisher,
            manifest: previous.manifest as NpmVersionManifest,
            tarball: previousTarball,
            tarballDigest: previous.tarball_digest,
          }
        : null,
      firstRelease: releaseCount === 0,
      scopeKey: `private:${context.config.ORG_ID}`,
      engineVersion: context.config.AUDIT_ENGINE_VERSION,
      existingPackageNames,
      cache: null,
      sandbox: null,
      llm: null,
          }),
        ),
      );
    } catch (error) {
      if (error instanceof IngestionError) {
        await auditIngestionRejection(context.pool, {
          orgId: context.config.ORG_ID,
          actor: publisher.username,
          packageName,
          error,
        });
        if (error.retryAfterSeconds) {
          reply.header("retry-after", String(error.retryAfterSeconds));
        }
        reply.code(error.statusCode).send({ error: error.message });
        return;
      }
      throw error;
    } finally {
      releaseSlot();
    }
    const { result } = audited;

    // Pre-flight exposes an explicit sandbox probe even when the static result
    // already blocks, so it stays a separate request-level result here.
    let sandbox = null;
    if (body.sandbox === true) {
      sandbox = await runSandbox(tarball, context.config);
    }
    reply.send({
      mode: "static",
      packageName,
      version,
      policyVersion: policy.version,
      result,
      sandbox,
    });
  });
}

import type { FastifyReply, FastifyRequest } from "fastify";
import semver from "semver";
import type { AppContext } from "../context.js";
import { assertPackageAccess, authenticatePublisher } from "../auth.js";
import {
  encodePackageName,
  normalizePackageName,
  validatePackageName,
} from "../npm/names.js";
import { proxyToVerdaccio } from "../proxy.js";
import {
  findReleaseByTarballFilename,
  findTarballRelease,
  getPackageReleaseGates,
  isDownloadable,
  isVisibleInPackument,
  type ReleaseGate,
} from "../registry-view.js";
import {
  buildDistTags,
  getDistTags,
  isBlocklisted,
  markArtifactMissing,
  recordInstallEvent,
} from "../serving.js";
import { isNoSuchKeyError } from "../storage.js";
import { SpoolError, spoolResponseBody } from "../spool.js";
import { createReadStream } from "node:fs";
import { readFile } from "node:fs/promises";
import { insertEvent } from "../releases.js";
import { auditUpstreamTarball } from "../upstream-audit.js";

interface PackumentVersion {
  dist?: {
    tarball?: string;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

interface Packument {
  name?: string;
  versions?: Record<string, PackumentVersion>;
  "dist-tags"?: Record<string, string>;
  time?: Record<string, string>;
  [key: string]: unknown;
}

const MAX_PACKUMENT_BYTES = 10 * 1024 * 1024;

async function readLimitedBody(response: Response, limit: number): Promise<Buffer> {
  const declared = Number(response.headers.get("content-length") ?? "0");
  if (declared > limit) throw new Error("Upstream tarball exceeds the configured size limit.");
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      const chunk = Buffer.from(next.value);
      total += chunk.length;
      if (total > limit) {
        await reader.cancel();
        throw new Error("Upstream tarball exceeds the configured size limit.");
      }
      chunks.push(chunk);
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks);
}

function forwardDownloadHeaders(response: Response, reply: FastifyReply): void {
  for (const name of ["content-type", "cache-control", "etag", "last-modified", "npm-notice"]) {
    const value = response.headers.get(name);
    if (value) reply.header(name, value);
  }
}

export function filterPackument(
  packument: Packument,
  statusByVersion: Map<string, ReleaseGate>,
  publicRegistryUrl: string,
  storedDistTags: Record<string, string> = {},
): boolean {
  const versions = packument.versions;
  if (!versions || Array.isArray(versions)) return false;

  let changed = false;

  for (const [version, manifest] of Object.entries(versions)) {
    const release = statusByVersion.get(version);
    if (release && !isVisibleInPackument(release)) {
      delete versions[version];
      changed = true;
      continue;
    }

    const tarball = manifest.dist?.tarball;
    if (typeof tarball === "string") {
      try {
        const parsed = new URL(tarball);
        manifest.dist!.tarball = `${publicRegistryUrl.replace(/\/+$/, "")}${
          parsed.pathname
        }${parsed.search}`;
      } catch {
        if (tarball.startsWith("/")) {
          manifest.dist!.tarball = `${publicRegistryUrl.replace(/\/+$/, "")}${tarball}`;
        }
      }
    }
  }

  // Dist-tag invariants hold on every response, even when no version was
  // filtered: tags come from the authoritative store, `latest` is the highest
  // stable visible version or absent, and tags to hidden versions are gone.
  const rebuiltTags = buildDistTags(storedDistTags, Object.keys(versions));
  if (
    JSON.stringify(packument["dist-tags"] ?? {}) !==
    JSON.stringify(rebuiltTags)
  ) {
    changed = true;
  }
  packument["dist-tags"] = rebuiltTags;

  if (packument.time) {
    for (const key of Object.keys(packument.time)) {
      if (key === "created" || key === "modified") continue;
      if (!versions[key]) delete packument.time[key];
    }
  }

  return changed;
}

export async function readHandler(
  request: FastifyRequest,
  reply: FastifyReply,
  context: AppContext,
): Promise<void> {
  const rawPath = String(
    (request.params as Record<string, string | undefined>)["*"] ?? "",
  );
  const path = normalizePackageName(rawPath);

  if (!path) {
    await authenticatePublisher(request, context.config);
    await proxyToVerdaccio(request, reply, context);
    return;
  }

  if (path.startsWith("-/")) {
    await authenticatePublisher(request, context.config);
    if (
      path !== "-/ping" &&
      !path.startsWith("-/npm/v1/security/")
    ) {
      reply.code(405).send({ error: "This npm control-plane operation is not supported." });
      return;
    }
    await proxyToVerdaccio(request, reply, context);
    return;
  }

  const tarballSeparator = path.indexOf("/-/");
  const requestedPackage =
    tarballSeparator === -1 ? path : path.slice(0, tarballSeparator);
  const packageNameError = validatePackageName(requestedPackage);
  if (packageNameError) {
    reply.code(400).send({ error: packageNameError });
    return;
  }
  const user = await authenticatePublisher(request, context.config);
  assertPackageAccess(user, requestedPackage, "read");

  if (tarballSeparator !== -1) {
    if (!["GET", "HEAD"].includes(request.method)) {
      reply.code(405).send({ error: "Tarball downloads are read-only." });
      return;
    }
    const packageName = path.slice(0, tarballSeparator);
    const filename = path.slice(tarballSeparator + 3);
    const versionMatch = /-(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)\.tgz$/i.exec(
      filename,
    );
    const requestedVersion =
      versionMatch && semver.valid(versionMatch[1]) ? versionMatch[1]! : null;

    const recordEvent = async (
      decision: "allowed" | "blocked",
      reason: string | null,
      version: string | null,
      digest: string | null,
    ): Promise<boolean> => {
      try {
        await recordInstallEvent(context.pool, {
          orgId: context.config.ORG_ID,
          actor: user.username,
          packageName,
          version,
          tarballDigest: digest,
          decision,
          reason,
          source: "tarball",
          requestId: request.id,
        });
        return true;
      } catch (error) {
        request.log.error(
          { err: error, packageName },
          "install event write failed; failing closed",
        );
        reply.code(503).send({ error: "Install event could not be recorded." });
        return false;
      }
    };

    // The blocklist precedes release state, the audit cache, and serving.
    if (
      await isBlocklisted(
        context.pool,
        context.config.ORG_ID,
        packageName,
        requestedVersion,
      )
    ) {
      if (!(await recordEvent("blocked", "blocklist", requestedVersion, null))) return;
      reply.code(404).send({ error: "Tarball not found." });
      return;
    }

    let release: Awaited<ReturnType<typeof findTarballRelease>> = null;

    if (filename && !filename.includes("/")) {
      const known = await findReleaseByTarballFilename(
        context.pool,
        context.config.ORG_ID,
        packageName,
        filename,
      );
      if (known) {
        if (
          await isBlocklisted(
            context.pool,
            context.config.ORG_ID,
            packageName,
            known.version,
            known.tarball_digest,
          )
        ) {
          if (
            !(await recordEvent("blocked", "blocklist", known.version, known.tarball_digest))
          ) {
            return;
          }
          reply.code(404).send({ error: "Tarball not found." });
          return;
        }
        if (!isDownloadable(known)) {
          if (
            !(await recordEvent(
              "blocked",
              `release_${known.status}`,
              known.version,
              known.tarball_digest,
            ))
          ) {
            return;
          }
          reply.code(404).send({
            error: `Release ${packageName}@${known.version} is ${known.status} and cannot be downloaded.`,
          });
          return;
        }
        release = known;
      }
    }

    if (release) {
      if (
        !(await recordEvent("allowed", null, release.version, release.tarball_digest))
      ) {
        return;
      }

      let present = true;
      try {
        present = await context.storage.exists(release.tarball_key);
      } catch (error) {
        if (isNoSuchKeyError(error)) {
          present = false;
        } else {
          request.log.error(
            { err: error, packageName },
            "artifact availability check failed",
          );
          reply.code(503).send({ error: "Artifact availability could not be verified." });
          return;
        }
      }
      if (!present) {
        await markArtifactMissing(
          context.pool,
          context.config.ORG_ID,
          release.id,
        ).catch(() => undefined);
        await insertEvent(context.pool, {
          orgId: context.config.ORG_ID,
          actor: "system:serving",
          action: "artifact.missing",
          subject: release.id,
          metadata: { packageName, version: release.version },
        }).catch(() => undefined);
        request.log.error(
          { packageName, version: release.version, releaseId: release.id },
          "approved artifact is missing from storage",
        );
        reply.code(503).send({
          error: "The approved artifact is missing from storage.",
        });
        return;
      }

      await proxyToVerdaccio(request, reply, context);
      return;
    }

    if (request.method === "GET") {
      if (!requestedVersion) {
        reply.code(403).send({
          error: "The upstream tarball name does not identify a valid package version.",
        });
        return;
      }
      const upstreamUrl = `${context.config.VERDACCIO_URL.replace(/\/+$/, "")}${request.url}`;
      let upstream: Response;
      try {
        upstream = await fetch(upstreamUrl, {
          headers: { accept: "application/octet-stream", "user-agent": "veripack-gateway/0.1" },
          redirect: "manual",
          signal: AbortSignal.timeout(context.config.PROXY_TIMEOUT_MS),
        });
      } catch (error) {
        request.log.error({ err: error, packageName, filename }, "upstream tarball fetch failed");
        reply.code(502).send({ error: "Registry upstream is unavailable." });
        return;
      }

      if (!upstream.ok) {
        let errorBody: Buffer;
        try {
          errorBody = await readLimitedBody(upstream, context.config.BODY_LIMIT_BYTES);
        } catch (error) {
          request.log.error({ err: error, packageName, filename }, "upstream tarball read failed");
          reply.code(502).send({ error: "Upstream tarball could not be safely read." });
          return;
        }
        forwardDownloadHeaders(upstream, reply);
        reply.code(upstream.status).send(errorBody);
        return;
      }

      // Stream to a bounded spool while hashing; never buffer the download.
      let spool;
      try {
        spool = await spoolResponseBody(upstream, {
          directory: context.config.UPSTREAM_SPOOL_DIR,
          maxBytes: context.config.INGEST_MAX_TARBALL_BYTES,
        });
      } catch (error) {
        if (error instanceof SpoolError && error.code === "too_large") {
          reply.code(413).send({ error: error.message });
          return;
        }
        request.log.error({ err: error, packageName, filename }, "upstream tarball spool failed");
        reply.code(502).send({ error: "Upstream tarball could not be safely read." });
        return;
      }

      let audit: Awaited<ReturnType<typeof auditUpstreamTarball>>;
      try {
        audit = await auditUpstreamTarball(
          context.pool,
          packageName,
          requestedVersion,
          await readFile(spool.path),
          context.config,
        );
      } catch (error) {
        await spool.cleanup();
        request.log.error(
          { err: error, packageName, filename },
          "upstream tarball audit failed closed",
        );
        reply.code(503).send({ error: "The upstream release could not be audited." });
        return;
      }
      if (audit.status === "blocked") {
        if (!(await recordEvent("blocked", "upstream_blocked", requestedVersion, audit.digest))) {
          await spool.cleanup();
          return;
        }
        await spool.cleanup();
        reply.code(403).send({
          error: "The upstream release was blocked by Veripack deterministic audit.",
          digest: audit.digest,
          summary: audit.summary,
        });
        return;
      }
      if (!(await recordEvent("allowed", null, requestedVersion, audit.digest))) {
        await spool.cleanup();
        return;
      }
      reply.header("x-veripack-upstream-audit", audit.digest);
      forwardDownloadHeaders(upstream, reply);
      // Serve from the spool and remove it when the response finishes.
      reply.raw.on("finish", () => void spool.cleanup());
      reply.raw.on("close", () => void spool.cleanup());
      reply.send(createReadStream(spool.path));
      return;
    }

    await proxyToVerdaccio(request, reply, context);
    return;
  }

  if (path.includes("/") && !path.startsWith("@")) {
    if (!["GET", "HEAD"].includes(request.method)) {
      reply.code(405).send({ error: "Package mutation is not supported at this endpoint." });
      return;
    }
    await proxyToVerdaccio(request, reply, context);
    return;
  }

  if (!["GET", "HEAD"].includes(request.method)) {
    reply.code(405).send({ error: "Package mutation is not supported at this endpoint." });
    return;
  }

  // The blocklist precedes the packument and the audit cache.
  if (await isBlocklisted(context.pool, context.config.ORG_ID, path)) {
    try {
      await recordInstallEvent(context.pool, {
        orgId: context.config.ORG_ID,
        actor: user.username,
        packageName: path,
        decision: "blocked",
        reason: "blocklist",
        source: "packument",
        requestId: request.id,
      });
    } catch (error) {
      request.log.error(
        { err: error, packageName: path },
        "install event write failed; failing closed",
      );
      reply.code(503).send({ error: "Install event could not be recorded." });
      return;
    }
    reply.code(404).send({ error: "Package not found." });
    return;
  }

  const base = context.config.VERDACCIO_URL.replace(/\/+$/, "");
  const queryIndex = request.url.indexOf("?");
  const query = queryIndex === -1 ? "" : request.url.slice(queryIndex);

  let upstream: Response;
  try {
    upstream = await fetch(`${base}/${encodePackageName(path)}${query}`, {
      headers: {
        accept: "application/json",
        "user-agent": "veripack-gateway/0.1",
      },
      signal: AbortSignal.timeout(30_000),
    });
  } catch (error) {
    request.log.error({ err: error, path }, "packument proxy failed");
    reply.code(502).send({ error: "Registry upstream is unavailable." });
    return;
  }

  if (!upstream.ok) {
    let bytes: Buffer;
    try {
      bytes = await readLimitedBody(upstream, MAX_PACKUMENT_BYTES);
    } catch {
      reply.code(502).send({ error: "Registry upstream response is too large." });
      return;
    }
    reply
      .code(upstream.status)
      .type(upstream.headers.get("content-type") ?? "application/json")
      .send(bytes);
    return;
  }

  let packument: Packument;
  try {
    packument = JSON.parse(
      (await readLimitedBody(upstream, MAX_PACKUMENT_BYTES)).toString("utf8"),
    ) as Packument;
  } catch {
    reply.code(502).send({ error: "Registry upstream returned invalid JSON." });
    return;
  }

  const [statusByVersion, storedDistTags] = await Promise.all([
    getPackageReleaseGates(context.pool, context.config.ORG_ID, path),
    getDistTags(context.pool, context.config.ORG_ID, path),
  ]);
  filterPackument(
    packument,
    statusByVersion,
    context.config.PUBLIC_REGISTRY_URL,
    storedDistTags,
  );

  try {
    await recordInstallEvent(context.pool, {
      orgId: context.config.ORG_ID,
      actor: user.username,
      packageName: path,
      decision: "allowed",
      source: "packument",
      requestId: request.id,
    });
  } catch (error) {
    request.log.error(
      { err: error, packageName: path },
      "install event write failed; failing closed",
    );
    reply.code(503).send({ error: "Install event could not be recorded." });
    return;
  }

  reply.header("cache-control", "no-store");
  reply.type("application/json").send(packument);
}

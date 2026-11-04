import type { Queryable } from "../db.js";
import {
  deserializeArtifactAnalysis,
  serializeArtifactAnalysis,
  type ArtifactAnalysis,
} from "./static.js";

export interface AuditCacheKey {
  scopeKey: string;
  tarballDigest: string;
  engineVersion: string;
}

export async function getCachedArtifact(
  db: Queryable,
  key: AuditCacheKey,
): Promise<ArtifactAnalysis | null> {
  const result = await db.query<{ artifact: unknown }>(
    `select artifact
     from audit_cache
     where scope_key = $1 and tarball_digest = $2 and engine_version = $3`,
    [key.scopeKey, key.tarballDigest, key.engineVersion],
  );

  const artifact = result.rows[0]?.artifact;
  return artifact === undefined ? null : deserializeArtifactAnalysis(artifact);
}

export async function putCachedArtifact(
  db: Queryable,
  key: AuditCacheKey,
  artifact: ArtifactAnalysis,
): Promise<void> {
  await db.query(
    `insert into audit_cache (
       scope_key, tarball_digest, engine_version, artifact
     )
     values ($1, $2, $3, $4)
     on conflict (scope_key, tarball_digest, engine_version) do nothing`,
    [
      key.scopeKey,
      key.tarballDigest,
      key.engineVersion,
      JSON.stringify(serializeArtifactAnalysis(artifact)),
    ],
  );
}

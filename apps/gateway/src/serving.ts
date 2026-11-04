import semver from "semver";
import type { Db, Queryable } from "./db.js";
import { insertEvent } from "./releases.js";

/**
 * The serving boundary: install events, the blocklist, Veripack-owned
 * dist-tags, and artifact holds. Registry reads consult this module before
 * any bytes are served.
 */

export type InstallDecision = "allowed" | "blocked";
export type InstallSource = "packument" | "tarball";

export interface InstallEventInput {
  orgId: string;
  actor: string;
  packageName: string;
  version?: string | null;
  tarballDigest?: string | null;
  decision: InstallDecision;
  reason?: string | null;
  source: InstallSource;
  requestId?: string | null;
}

/**
 * Writes an install event synchronously. Callers must treat a failure as
 * fail-closed (503, no bytes), for allowed and blocked attempts alike.
 */
export async function recordInstallEvent(
  db: Queryable,
  input: InstallEventInput,
): Promise<void> {
  await db.query(
    `insert into install_events (
       org_id, actor, package_name, version, tarball_digest, decision,
       reason, source, request_id
     )
     values ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
    [
      input.orgId,
      input.actor,
      input.packageName,
      input.version ?? null,
      input.tarballDigest ?? null,
      input.decision,
      input.reason ?? null,
      input.source,
      input.requestId ?? null,
    ],
  );
}

export interface InstallEventRow {
  id: string;
  org_id: string;
  actor: string;
  package_name: string;
  version: string | null;
  tarball_digest: string | null;
  decision: InstallDecision;
  reason: string | null;
  source: InstallSource;
  request_id: string | null;
  created_at: Date;
}

export async function listInstallEvents(
  db: Queryable,
  orgId: string,
  options: { packageName?: string; limit?: number } = {},
): Promise<InstallEventRow[]> {
  const result = await db.query<InstallEventRow>(
    `select * from install_events
      where org_id = $1
        and ($2::text is null or package_name = $2)
      order by created_at desc
      limit $3`,
    [orgId, options.packageName ?? null, options.limit ?? 100],
  );
  return result.rows;
}

// ---------------------------------------------------------------------------
// Blocklist
// ---------------------------------------------------------------------------

export interface BlocklistEntryRow {
  id: string;
  org_id: string;
  package_name: string;
  version: string | null;
  tarball_digest: string | null;
  reason: string;
  created_by: string;
  created_at: Date;
  active: boolean;
  revoked_at: Date | null;
}

export async function createBlocklistEntry(
  db: Db,
  input: {
    orgId: string;
    packageName: string;
    version?: string | null;
    tarballDigest?: string | null;
    reason: string;
    createdBy: string;
  },
): Promise<BlocklistEntryRow> {
  const result = await db.query<BlocklistEntryRow>(
    `insert into blocklist_entries (
       org_id, package_name, version, tarball_digest, reason, created_by
     )
     values ($1, $2, $3, $4, $5, $6)
     returning *, true as active, null::timestamptz as revoked_at`,
    [
      input.orgId,
      input.packageName,
      input.version ?? null,
      input.tarballDigest ?? null,
      input.reason,
      input.createdBy,
    ],
  );
  const entry = result.rows[0]!;
  await insertEvent(db, {
    orgId: input.orgId,
    actor: input.createdBy,
    action: "blocklist.entry_created",
    subject: input.packageName,
    metadata: {
      entryId: entry.id,
      version: entry.version,
      tarballDigest: entry.tarball_digest,
      reason: input.reason,
    },
  });
  return entry;
}

export async function revokeBlocklistEntry(
  db: Db,
  input: { orgId: string; entryId: string; reason: string; revokedBy: string },
): Promise<BlocklistEntryRow | null> {
  const inserted = await db.query<{ id: string }>(
    `insert into blocklist_revocations (entry_id, org_id, reason, revoked_by)
     select id, org_id, $3, $4
       from blocklist_entries
      where id = $1 and org_id = $2
     on conflict (entry_id) do nothing
     returning id`,
    [input.entryId, input.orgId, input.reason, input.revokedBy],
  );
  if (inserted.rows.length === 0) return null;

  const entry = await listBlocklistEntries(db, input.orgId);
  const revoked = entry.find((row) => row.id === input.entryId) ?? null;
  if (revoked) {
    await insertEvent(db, {
      orgId: input.orgId,
      actor: input.revokedBy,
      action: "blocklist.entry_revoked",
      subject: revoked.package_name,
      metadata: { entryId: revoked.id, reason: input.reason },
    });
  }
  return revoked;
}

export async function listBlocklistEntries(
  db: Queryable,
  orgId: string,
): Promise<BlocklistEntryRow[]> {
  const result = await db.query<BlocklistEntryRow>(
    `select e.*,
            (r.id is null) as active,
            r.created_at as revoked_at
       from blocklist_entries e
       left join blocklist_revocations r on r.entry_id = e.id
      where e.org_id = $1
      order by e.created_at desc`,
    [orgId],
  );
  return result.rows;
}

export async function isBlocklisted(
  db: Queryable,
  orgId: string,
  packageName: string,
  version?: string | null,
  tarballDigest?: string | null,
): Promise<boolean> {
  const result = await db.query<{ blocked: boolean }>(
    `select exists(
       select 1
         from blocklist_entries e
        where e.org_id = $1
          and e.package_name = $2
          and (e.version is null or e.version = $3)
          and (e.tarball_digest is null or e.tarball_digest = $4)
          and not exists (
            select 1 from blocklist_revocations r where r.entry_id = e.id
          )
     ) as blocked`,
    [orgId, packageName, version ?? null, tarballDigest ?? null],
  );
  return result.rows[0]?.blocked === true;
}

// ---------------------------------------------------------------------------
// Dist-tags (Veripack authoritative; Verdaccio is a mirror)
// ---------------------------------------------------------------------------

export class DistTagError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DistTagError";
  }
}

export async function getDistTags(
  db: Queryable,
  orgId: string,
  packageName: string,
): Promise<Record<string, string>> {
  const result = await db.query<{ tag: string; version: string }>(
    `select tag, version from dist_tags
      where org_id = $1 and package_name = $2`,
    [orgId, packageName],
  );
  return Object.fromEntries(result.rows.map((row) => [row.tag, row.version]));
}

/** Highest stable version, or null when only prereleases are visible. */
export function computeLatestTag(visibleVersions: string[]): string | null {
  const stable = visibleVersions.filter(
    (version) => semver.valid(version) && !semver.prerelease(version),
  );
  return semver.rsort(stable)[0] ?? null;
}

/**
 * Rebuilds a packument's dist-tags from the authoritative store plus the
 * computed `latest`. Tags pointing at hidden versions are removed.
 */
export function buildDistTags(
  stored: Record<string, string>,
  visibleVersions: string[],
): Record<string, string> {
  const visible = new Set(visibleVersions);
  const result: Record<string, string> = {};
  for (const [tag, version] of Object.entries(stored)) {
    if (tag !== "latest" && visible.has(version)) result[tag] = version;
  }
  const latest = computeLatestTag(visibleVersions);
  if (latest) result.latest = latest;
  return result;
}

export async function setDistTag(
  db: Db,
  input: {
    orgId: string;
    packageName: string;
    tag: string;
    version: string;
    updatedBy: string;
    allowBackward?: boolean;
    source: "admin" | "publisher";
  },
): Promise<void> {
  const current = await getDistTags(db, input.orgId, input.packageName);
  const existing = current[input.tag];
  if (
    existing &&
    existing !== input.version &&
    semver.valid(existing) &&
    semver.valid(input.version) &&
    semver.lt(input.version, existing) &&
    !input.allowBackward
  ) {
    throw new DistTagError(
      `Dist-tag "${input.tag}" already points at ${existing}; moving it backward to ${input.version} requires an admin override.`,
    );
  }

  await db.query(
    `insert into dist_tags (org_id, package_name, tag, version, updated_by)
     values ($1, $2, $3, $4, $5)
     on conflict (org_id, package_name, tag) do update
        set version = excluded.version,
            updated_by = excluded.updated_by,
            updated_at = now()`,
    [input.orgId, input.packageName, input.tag, input.version, input.updatedBy],
  );
  await insertEvent(db, {
    orgId: input.orgId,
    actor: input.updatedBy,
    action: "package.dist_tag_set",
    subject: input.packageName,
    metadata: {
      packageName: input.packageName,
      tag: input.tag,
      version: input.version,
      previousVersion: existing ?? null,
      source: input.source,
    },
  });
}

export async function deleteDistTag(
  db: Db,
  input: {
    orgId: string;
    packageName: string;
    tag: string;
    updatedBy: string;
    source: "admin" | "publisher";
  },
): Promise<boolean> {
  const result = await db.query<{ tag: string }>(
    `delete from dist_tags
      where org_id = $1 and package_name = $2 and tag = $3
      returning tag`,
    [input.orgId, input.packageName, input.tag],
  );
  if (result.rows.length === 0) return false;
  await insertEvent(db, {
    orgId: input.orgId,
    actor: input.updatedBy,
    action: "package.dist_tag_deleted",
    subject: input.packageName,
    metadata: {
      packageName: input.packageName,
      tag: input.tag,
      source: input.source,
    },
  });
  return true;
}

// ---------------------------------------------------------------------------
// Artifact availability and holds
// ---------------------------------------------------------------------------

export interface ArtifactStateRow {
  release_id: string;
  org_id: string;
  state: "present" | "missing";
  missing_since: Date | null;
  last_checked_at: Date;
  updated_at: Date;
}

export async function getArtifactState(
  db: Queryable,
  releaseId: string,
): Promise<ArtifactStateRow | null> {
  const result = await db.query<ArtifactStateRow>(
    "select * from release_artifacts where release_id = $1",
    [releaseId],
  );
  return result.rows[0] ?? null;
}

export async function markArtifactMissing(
  db: Queryable,
  orgId: string,
  releaseId: string,
): Promise<void> {
  await db.query(
    `insert into release_artifacts (release_id, org_id, state, missing_since)
     values ($1, $2, 'missing', now())
     on conflict (release_id) do update
        set state = 'missing',
            missing_since = coalesce(release_artifacts.missing_since, now()),
            last_checked_at = now(),
            updated_at = now()`,
    [releaseId, orgId],
  );
  await db.query(
    `insert into release_holds (org_id, release_id, reason)
     values ($1, $2, 'artifact_missing')
     on conflict (release_id) where resolution is null do nothing`,
    [orgId, releaseId],
  );
}

export async function markArtifactPresent(
  db: Queryable,
  orgId: string,
  releaseId: string,
): Promise<void> {
  await db.query(
    `insert into release_artifacts (release_id, org_id, state)
     values ($1, $2, 'present')
     on conflict (release_id) do update
        set state = 'present',
            missing_since = null,
            last_checked_at = now(),
            updated_at = now()`,
    [releaseId, orgId],
  );
}

export async function resolveReleaseHold(
  db: Queryable,
  releaseId: string,
  resolution: "reuploaded" | "rejected",
  resolvedBy: string,
): Promise<void> {
  await db.query(
    `update release_holds
        set resolution = $2,
            resolved_by = $3,
            resolved_at = now()
      where release_id = $1
        and resolution is null`,
    [releaseId, resolution, resolvedBy],
  );
}

export async function hasOpenHold(
  db: Queryable,
  releaseId: string,
): Promise<boolean> {
  const result = await db.query<{ open: boolean }>(
    `select exists(
       select 1 from release_holds
        where release_id = $1 and resolution is null
     ) as open`,
    [releaseId],
  );
  return result.rows[0]?.open === true;
}

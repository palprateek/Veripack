import type { ReleaseStatus } from "@veripack/shared";
import type { Queryable } from "./db.js";
import type { ReleaseRow } from "./releases.js";

/**
 * The installability boundary for registry reads. Every consumer asks this
 * module instead of re-deriving the predicate from status and replay state.
 */
export interface ReleaseGate {
  status: ReleaseStatus;
  replay_state: string;
}

const INSTALLABLE_SQL =
  "(status in ('approved', 'overridden') and replay_state = 'succeeded')";

export function isInstallable(release: ReleaseGate): boolean {
  return (
    (release.status === "approved" || release.status === "overridden") &&
    release.replay_state === "succeeded"
  );
}

/**
 * Downloadable is exactly installable: a yanked (or pending, rejected, or
 * quarantined) release is never served, even to existing lockfiles.
 */
export function isDownloadable(release: ReleaseGate): boolean {
  return isInstallable(release);
}

export function isVisibleInPackument(release: ReleaseGate): boolean {
  return isInstallable(release);
}

export async function findTarballRelease(
  db: Queryable,
  orgId: string,
  packageName: string,
  filename: string,
): Promise<ReleaseRow | null> {
  const result = await db.query<ReleaseRow>(
    `select * from releases
     where org_id = $1 and package_name = $2 and tarball_filename = $3
       and ${INSTALLABLE_SQL}
     order by created_at desc
       limit 1`,
    [orgId, packageName, filename],
  );
  return result.rows[0] ?? null;
}

/** Any release for a tarball filename, regardless of state (blocked checks). */
export async function findReleaseByTarballFilename(
  db: Queryable,
  orgId: string,
  packageName: string,
  filename: string,
): Promise<ReleaseRow | null> {
  const result = await db.query<ReleaseRow>(
    `select * from releases
     where org_id = $1 and package_name = $2 and tarball_filename = $3
     order by created_at desc
       limit 1`,
    [orgId, packageName, filename],
  );
  return result.rows[0] ?? null;
}

export async function getPreviousInstallableRelease(
  db: Queryable,
  orgId: string,
  packageName: string,
  before: Date,
): Promise<ReleaseRow | null> {
  const result = await db.query<ReleaseRow>(
    `select * from releases
      where org_id = $1 and package_name = $2 and created_at < $3
        and ${INSTALLABLE_SQL}
      order by created_at desc
     limit 1`,
    [orgId, packageName, before],
  );
  return result.rows[0] ?? null;
}

export async function countInstallableReleases(
  db: Queryable,
  orgId: string,
  packageName: string,
): Promise<number> {
  const result = await db.query<{ count: string }>(
    `select count(*)::text as count
       from releases
      where org_id = $1
        and package_name = $2
        and ${INSTALLABLE_SQL}`,
    [orgId, packageName],
  );
  return Number(result.rows[0]?.count ?? "0");
}

export async function hasInstallableRelease(
  db: Queryable,
  orgId: string,
  packageName: string,
): Promise<boolean> {
  const result = await db.query<{ has_release: boolean }>(
    `select exists(
       select 1 from releases
        where org_id = $1 and package_name = $2 and ${INSTALLABLE_SQL}
     ) as has_release`,
    [orgId, packageName],
  );
  return result.rows[0]?.has_release === true;
}

export async function getPackageReleaseGates(
  db: Queryable,
  orgId: string,
  packageName: string,
): Promise<Map<string, ReleaseGate>> {
  const result = await db.query<{
    version: string;
    status: ReleaseStatus;
    replay_state: string;
  }>(
    `select version, status, replay_state
       from releases
      where org_id = $1 and package_name = $2`,
    [orgId, packageName],
  );
  return new Map(result.rows.map((row) => [row.version, row]));
}

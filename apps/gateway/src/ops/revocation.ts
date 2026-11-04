import type { AuditPolicy } from "@veripack/shared";
import type { Db } from "../db.js";
import { insertEvent, type ReleaseRow } from "../releases.js";

/**
 * V2 threshold-based revocation (spec row 3): team policy flags young,
 * low-install releases for quarantine review. Flagging never quarantines
 * automatically — a human admin decides.
 */
export async function evaluateRevocationFlags(
  db: Db,
  orgId: string,
  policy: AuditPolicy,
  now: Date = new Date(),
): Promise<ReleaseRow[]> {
  const { flagBelowInstalls, withinDays } = policy.revocation;
  if (flagBelowInstalls <= 0) return [];

  const candidates = await db.query<ReleaseRow & { installs: string }>(
    `select r.*,
            (select count(*)::text from install_events e
              where e.org_id = r.org_id
                and e.package_name = r.package_name
                and e.version = r.version
                and e.decision = 'allowed') as installs
       from releases r
      where r.org_id = $1
        and r.status in ('approved', 'overridden')
        and r.created_at > $2::timestamptz
        and not exists (
          select 1 from audit_events flagged
           where flagged.subject = r.id::text
             and flagged.action = 'release.revocation_flagged'
        )
      order by r.created_at asc`,
    [orgId, new Date(now.getTime() - withinDays * 24 * 60 * 60 * 1_000)],
  );

  const flagged: ReleaseRow[] = [];
  for (const release of candidates.rows) {
    if (Number(release.installs) >= flagBelowInstalls) continue;
    await insertEvent(db, {
      orgId,
      actor: "system:revocation",
      action: "release.revocation_flagged",
      subject: release.id,
      metadata: {
        packageName: release.package_name,
        version: release.version,
        installs: Number(release.installs),
        flagBelowInstalls,
        withinDays,
      },
    });
    flagged.push(release);
  }
  return flagged;
}

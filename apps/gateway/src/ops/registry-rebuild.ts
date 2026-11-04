import type { Db } from "../db.js";
import { isUniqueViolation, type ReleaseRow } from "../releases.js";
import { enqueueReplayJob } from "../replay-jobs.js";

export interface RebuildReport {
  queued: string[];
  alreadySucceeded: string[];
  unresolved: Array<{ releaseId: string; packageName: string; version: string; reason: string }>;
}

/**
 * Rebuilds Verdaccio state from the database: every approved or overridden
 * release without a succeeded replay gets a durable job, in creation order.
 * Digest verification happens in the replay worker. Idempotent: releases
 * already replayed (or with an active job) are skipped.
 */
export async function rebuildRegistry(
  db: Db,
  artifactExists: (release: ReleaseRow) => Promise<boolean>,
): Promise<RebuildReport> {
  const result = await db.query<ReleaseRow>(
    `select * from releases
      where status in ('approved', 'overridden')
      order by created_at asc`,
  );

  const report: RebuildReport = {
    queued: [],
    alreadySucceeded: [],
    unresolved: [],
  };

  for (const release of result.rows) {
    if (release.replay_state === "succeeded") {
      report.alreadySucceeded.push(release.id);
      continue;
    }
    if (!(await artifactExists(release))) {
      report.unresolved.push({
        releaseId: release.id,
        packageName: release.package_name,
        version: release.version,
        reason: "artifact_missing",
      });
      continue;
    }
    try {
      await enqueueReplayJob(db, {
        orgId: release.org_id,
        releaseId: release.id,
      });
      report.queued.push(release.id);
    } catch (error) {
      if (isUniqueViolation(error)) {
        // An active job already exists; rebuild stays idempotent.
        report.queued.push(release.id);
        continue;
      }
      throw error;
    }
  }

  return report;
}

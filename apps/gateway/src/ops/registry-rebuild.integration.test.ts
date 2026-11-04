import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { rebuildRegistry } from "./registry-rebuild.js";
import {
  createTestDatabase,
  type TestDatabase,
} from "../test-support/integration-db.js";

const ORG = "org-1";

async function seed(
  db: TestDatabase,
  status: string,
  replayState: string,
  version: string,
): Promise<string> {
  const releaseId = randomUUID();
  await db.pool.query(
    `insert into releases (
       id, org_id, package_name, version, tarball_digest, tarball_key,
       tarball_filename, payload_key, publisher, manifest, status, replay_state
     )
     values ($1, $2, '@acme/widget', $3, 'digest', $4, $5, $6, 'publisher-1',
             '{}'::jsonb, $7, $8)`,
    [
      releaseId,
      ORG,
      version,
      `tarballs/${releaseId}.tgz`,
      `widget-${version}.tgz`,
      `payloads/${releaseId}.json`,
      status,
      replayState,
    ],
  );
  return releaseId;
}

describe("registry rebuild (integration)", () => {
  it("queues only releases that still need replay, in creation order", async () => {
    const db = await createTestDatabase();
    try {
      const done = await seed(db, "approved", "succeeded", "1.0.0");
      const failed = await seed(db, "approved", "failed", "1.1.0");
      const missing = await seed(db, "overridden", "failed", "1.2.0");
      await seed(db, "yanked", "succeeded", "1.3.0");

      const report = await rebuildRegistry(db.pool, async (release) =>
        release.id !== missing,
      );

      expect(report.alreadySucceeded).toEqual([done]);
      expect(report.queued).toEqual([failed]);
      expect(report.unresolved).toEqual([
        {
          releaseId: missing,
          packageName: "@acme/widget",
          version: "1.2.0",
          reason: "artifact_missing",
        },
      ]);

      const jobs = await db.pool.query<{ release_id: string; state: string }>(
        "select release_id, state from replay_jobs",
      );
      expect(jobs.rows).toEqual([{ release_id: failed, state: "queued" }]);

      // Idempotent: a second run does not create duplicate active jobs.
      const again = await rebuildRegistry(db.pool, async () => true);
      expect(again.queued).toEqual([failed, missing]);
      const count = await db.pool.query<{ count: string }>(
        "select count(*)::text as count from replay_jobs",
      );
      expect(count.rows[0]?.count).toBe("2");
    } finally {
      await db.close();
    }
  });
});

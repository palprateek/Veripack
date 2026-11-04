import { createHash, randomUUID } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { FastifyInstance } from "fastify";
import { config as defaultConfig, type Config } from "./config.js";
import {
  findReleaseByTarballFilename,
  findTarballRelease,
} from "./registry-view.js";
import {
  DistTagError,
  buildDistTags,
  createBlocklistEntry,
  getArtifactState,
  hasOpenHold,
  isBlocklisted,
  listInstallEvents,
  markArtifactMissing,
  markArtifactPresent,
  recordInstallEvent,
  resolveReleaseHold,
  revokeBlocklistEntry,
  setDistTag,
} from "./serving.js";
import { buildServer } from "./server.js";
import {
  createTestDatabase,
  type TestDatabase,
} from "./test-support/integration-db.js";

const ORG = "org-1";
const TARBALL = Buffer.from("serving test tarball");
const DIGEST = createHash("sha256").update(TARBALL).digest("hex");

async function seedRelease(
  db: TestDatabase,
  status: string,
  version = "1.0.0",
): Promise<string> {
  const releaseId = randomUUID();
  await db.pool.query(
    `insert into releases (
       id, org_id, package_name, version, tarball_digest, tarball_key,
       tarball_filename, payload_key, publisher, manifest, status, replay_state
     )
     values ($1, $2, '@acme/widget', $3, $4, $5, $6, $7, 'publisher-1',
             '{}'::jsonb, $8, 'succeeded')`,
    [
      releaseId,
      ORG,
      version,
      DIGEST,
      `tarballs/${releaseId}.tgz`,
      `widget-${version}.tgz`,
      `payloads/${releaseId}.json`,
      status,
    ],
  );
  return releaseId;
}

describe("serving boundary (integration)", () => {
  it("finds only installable tarball releases", async () => {
    const db = await createTestDatabase();
    try {
      await seedRelease(db, "yanked");
      expect(
        await findTarballRelease(db.pool, ORG, "@acme/widget", "widget-1.0.0.tgz"),
      ).toBeNull();
      const known = await findReleaseByTarballFilename(
        db.pool,
        ORG,
        "@acme/widget",
        "widget-1.0.0.tgz",
      );
      expect(known?.status).toBe("yanked");
    } finally {
      await db.close();
    }
  });

  it("blocks by package, version, and digest until revoked", async () => {
    const db = await createTestDatabase();
    try {
      const entry = await createBlocklistEntry(db.pool, {
        orgId: ORG,
        packageName: "@acme/widget",
        version: "1.0.0",
        reason: "Compromised release.",
        createdBy: "admin-1",
      });
      expect(await isBlocklisted(db.pool, ORG, "@acme/widget")).toBe(false);
      expect(await isBlocklisted(db.pool, ORG, "@acme/widget", "1.0.0")).toBe(true);
      expect(await isBlocklisted(db.pool, ORG, "@acme/widget", "2.0.0")).toBe(false);

      const revoked = await revokeBlocklistEntry(db.pool, {
        orgId: ORG,
        entryId: entry.id,
        reason: "False positive.",
        revokedBy: "admin-2",
      });
      expect(revoked?.active).toBe(false);
      expect(await isBlocklisted(db.pool, ORG, "@acme/widget", "1.0.0")).toBe(false);
    } finally {
      await db.close();
    }
  });

  it("records install events and refuses to mutate them", async () => {
    const db = await createTestDatabase();
    try {
      await recordInstallEvent(db.pool, {
        orgId: ORG,
        actor: "installer",
        packageName: "@acme/widget",
        version: "1.0.0",
        tarballDigest: DIGEST,
        decision: "blocked",
        reason: "release_yanked",
        source: "tarball",
        requestId: "req-1",
      });
      const events = await listInstallEvents(db.pool, ORG, {});
      expect(events).toHaveLength(1);
      expect(events[0]?.decision).toBe("blocked");

      await expect(
        db.pool.query("update install_events set decision = 'allowed'"),
      ).rejects.toThrow(/append-only/);
      await expect(
        db.pool.query("delete from install_events"),
      ).rejects.toThrow(/append-only/);
    } finally {
      await db.close();
    }
  });

  it("rejects backward dist-tag moves without an admin override", async () => {
    const db = await createTestDatabase();
    try {
      await setDistTag(db.pool, {
        orgId: ORG,
        packageName: "@acme/widget",
        tag: "next",
        version: "2.0.0",
        updatedBy: "publisher-1",
        source: "publisher",
      });
      await expect(
        setDistTag(db.pool, {
          orgId: ORG,
          packageName: "@acme/widget",
          tag: "next",
          version: "1.0.0",
          updatedBy: "publisher-1",
          source: "publisher",
        }),
      ).rejects.toBeInstanceOf(DistTagError);

      await setDistTag(db.pool, {
        orgId: ORG,
        packageName: "@acme/widget",
        tag: "next",
        version: "1.0.0",
        updatedBy: "admin-1",
        allowBackward: true,
        source: "admin",
      });
    } finally {
      await db.close();
    }
  });

  it("computes latest from stable versions and drops hidden tags", () => {
    expect(
      buildDistTags({ next: "2.0.0-beta.1", beta: "1.0.0" }, [
        "1.0.0",
        "2.0.0-beta.1",
      ]),
    ).toEqual({ next: "2.0.0-beta.1", beta: "1.0.0", latest: "1.0.0" });
    expect(buildDistTags({}, ["2.0.0-beta.1"])).toEqual({});
  });

  it("holds a missing artifact until re-upload resolves it", async () => {
    const db = await createTestDatabase();
    try {
      const releaseId = await seedRelease(db, "approved");
      await markArtifactMissing(db.pool, ORG, releaseId);
      expect((await getArtifactState(db.pool, releaseId))?.state).toBe("missing");
      expect(await hasOpenHold(db.pool, releaseId)).toBe(true);

      await markArtifactPresent(db.pool, ORG, releaseId);
      await resolveReleaseHold(db.pool, releaseId, "reuploaded", "admin-1");
      expect((await getArtifactState(db.pool, releaseId))?.state).toBe("present");
      expect(await hasOpenHold(db.pool, releaseId)).toBe(false);
    } finally {
      await db.close();
    }
  });
});

describe("artifact re-upload (integration)", () => {
  const apps: FastifyInstance[] = [];
  afterEach(async () => {
    await Promise.all(apps.splice(0).map((app) => app.close()));
  });

  function testConfig(): Config {
    return {
      ...defaultConfig,
      LOG_LEVEL: "silent",
      AUTH_MODE: "static",
      ADMIN_TOKEN: "admin-secret",
      ADMIN_USER: "operator",
      ORG_ID: ORG,
      RATE_LIMIT_BACKEND: "memory",
    };
  }

  it("rejects mismatched bytes and accepts bytes matching the digest", async () => {
    const db = await createTestDatabase();
    try {
      const releaseId = await seedRelease(db, "approved");
      await markArtifactMissing(db.pool, ORG, releaseId);
      const putTarball = vi.fn(async () => undefined);
      const app = await buildServer({
        config: testConfig(),
        pool: db.pool,
        storage: { putTarball },
        verdaccio: { isReachable: async () => true },
        boss: {},
        lifecycle: {},
      } as never);
      apps.push(app);
      const headers = { authorization: "Bearer admin-secret" };

      const mismatch = await app.inject({
        method: "POST",
        url: `/admin/releases/${releaseId}/artifact/reupload`,
        headers,
        payload: {
          tarballBase64: Buffer.from("wrong bytes").toString("base64"),
        },
      });
      expect(mismatch.statusCode).toBe(409);
      expect(putTarball).not.toHaveBeenCalled();

      const accepted = await app.inject({
        method: "POST",
        url: `/admin/releases/${releaseId}/artifact/reupload`,
        headers,
        payload: { tarballBase64: TARBALL.toString("base64") },
      });
      expect(accepted.statusCode).toBe(200);
      expect(putTarball).toHaveBeenCalledTimes(1);
      expect((await getArtifactState(db.pool, releaseId))?.state).toBe("present");
      expect(await hasOpenHold(db.pool, releaseId)).toBe(false);
    } finally {
      await db.close();
    }
  });
});

import { createHash, randomUUID } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as tar from "tar";
import { describe, expect, it } from "vitest";
import type { Signal } from "@veripack/shared";
import { config as defaultConfig, type Config } from "./config.js";
import {
  createTestDatabase,
  type TestDatabase,
} from "./test-support/integration-db.js";
import {
  auditUpstreamTarball,
  forceUpstreamReaudit,
} from "./upstream-audit.js";

const ORG = "org-1";

function testConfig(overrides: Partial<Config> = {}): Config {
  return {
    ...defaultConfig,
    ORG_ID: ORG,
    AUDIT_POLICY_VERSION: "v1-default-1",
    AUDIT_POLICY_JSON: "{}",
    ...overrides,
  };
}

async function safeTarball(): Promise<Buffer> {
  const directory = await mkdtemp(join(tmpdir(), "veripack-upstream-it-"));
  try {
    await mkdir(join(directory, "package"), { recursive: true });
    await writeFile(
      join(directory, "package", "package.json"),
      JSON.stringify({ name: "left-pad", version: "1.0.0" }),
    );
    await writeFile(join(directory, "package", "index.js"), "module.exports = 1;\n");
    const chunks: Buffer[] = [];
    const stream = tar.c({ cwd: directory, gzip: true, portable: true }, [
      "package",
    ]);
    stream.on("data", (chunk: Buffer) => chunks.push(chunk));
    await new Promise<void>((resolve, reject) => {
      stream.on("end", resolve);
      stream.on("error", reject);
    });
    return Buffer.concat(chunks);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

const docsSignal: Signal = {
  type: "docs_tests_only",
  ruleId: "docs-tests-only",
  severity: "info",
  source: "deterministic",
  message: "Only documentation and test files changed.",
};

async function seedCacheRow(
  db: TestDatabase,
  tarball: Buffer,
  options: { policyVersion: string; expiresAt: string },
): Promise<void> {
  const digest = createHash("sha256").update(tarball).digest("hex");
  await db.pool.query(
    `insert into upstream_audits (
       tarball_digest, package_name, version, engine_version, ruleset_version,
       intel_version, policy_version, status, safety_verdict, intent_verdict,
       risk_tier, policy_result, signals, change_set, summary, expires_at
     )
     values ($1, 'left-pad', '1.0.0', $2, 'v1', 'v1', $3, 'audited', 'clear',
             'matches', 'low', 'pass', $4::jsonb, '{}'::jsonb, 'Cached.',
             $5::timestamptz)`,
    [
      digest,
      testConfig().AUDIT_ENGINE_VERSION,
      options.policyVersion,
      JSON.stringify([docsSignal]),
      options.expiresAt,
    ],
  );
}

async function rowCount(db: TestDatabase): Promise<number> {
  const result = await db.pool.query<{ count: string }>(
    "select count(*)::text as count from upstream_audits",
  );
  return Number(result.rows[0]?.count ?? "0");
}

describe("upstream audit cache (integration)", () => {
  it("re-evaluates stored evidence when the policy changes", async () => {
    const db = await createTestDatabase();
    try {
      const tarball = await safeTarball();
      await seedCacheRow(db, tarball, {
        policyVersion: "old-policy-1",
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      });

      const result = await auditUpstreamTarball(
        db.pool,
        "left-pad",
        "1.0.0",
        tarball,
        testConfig({
          AUDIT_POLICY_VERSION: "team-ban-1",
          AUDIT_POLICY_JSON: JSON.stringify({
            packages: { banned: ["left-pad"] },
          }),
        }),
      );

      expect(result.status).toBe("blocked");
      expect(result.policyResult).toBe("block");
      // The recomputed outcome is cached under the current policy version.
      expect(await rowCount(db)).toBe(2);
    } finally {
      await db.close();
    }
  });

  it("ignores expired rows, re-audits, and honors force re-audit", async () => {
    const db = await createTestDatabase();
    try {
      const tarball = await safeTarball();
      await seedCacheRow(db, tarball, {
        policyVersion: "v1-default-1",
        expiresAt: new Date(Date.now() - 60_000).toISOString(),
      });

      const result = await auditUpstreamTarball(
        db.pool,
        "left-pad",
        "1.0.0",
        tarball,
        testConfig(),
      );
      expect(result.status).toBe("audited");
      // The expired row is refreshed in place under the same cache key.
      expect(await rowCount(db)).toBe(1);

      const deleted = await forceUpstreamReaudit(db.pool, {
        packageName: "left-pad",
      });
      expect(deleted).toBe(1);
      expect(await rowCount(db)).toBe(0);
    } finally {
      await db.close();
    }
  });

  it("keys the cache by ruleset version", async () => {
    const db = await createTestDatabase();
    try {
      const tarball = await safeTarball();
      await seedCacheRow(db, tarball, {
        policyVersion: "v1-default-1",
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      });

      const result = await auditUpstreamTarball(
        db.pool,
        "left-pad",
        "1.0.0",
        tarball,
        testConfig({ AUDIT_RULESET_VERSION: "v2" }),
      );
      expect(result.status).toBe("audited");
      // Ruleset v2 missed the v1 row and analyzed fresh.
      expect(await rowCount(db)).toBe(2);
      void randomUUID();
    } finally {
      await db.close();
    }
  });
});

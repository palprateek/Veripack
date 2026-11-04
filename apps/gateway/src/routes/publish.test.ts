import { createHash } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { FastifyInstance } from "fastify";
import { config as defaultConfig, type Config } from "../config.js";
import type { ReleaseRow } from "../releases.js";
import { buildServer } from "../server.js";

const TARBALL = Buffer.from("pretend this is a gzipped tarball");

function testConfig(): Config {
  return {
    ...defaultConfig,
    LOG_LEVEL: "silent",
    AUTH_MODE: "static",
    VERIPACK_TOKEN: "publisher-secret",
    ADMIN_TOKEN: "admin-secret",
    DEFAULT_PUBLISHER: "publisher",
    ORG_ID: "org-a",
    ALLOW_UNSCOPED_NAMES: true,
    RATE_LIMIT_BACKEND: "memory",
  };
}

function makeRelease(overrides: Partial<ReleaseRow> = {}): ReleaseRow {
  return {
    id: "11111111-1111-1111-1111-111111111111",
    org_id: "org-a",
    package_name: "@team/pkg",
    version: "1.0.0",
    tarball_digest: "digest",
    tarball_key: "tarballs/pkg-1.0.0.tgz",
    tarball_filename: "pkg-1.0.0.tgz",
    payload_key: "payloads/pkg-1.0.0.json",
    integrity: null,
    shasum: null,
    status: "approved",
    replay_state: "succeeded",
    replay_job_id: null,
    replay_started_at: null,
    publisher: "publisher",
    intent: "Add a helper.",
    manifest: {},
    created_at: new Date("2026-01-01T00:00:00.000Z"),
    updated_at: new Date("2026-01-01T00:00:00.000Z"),
    ...overrides,
  };
}

function makePool(options: {
  owned?: boolean;
  release?: ReleaseRow | null;
  existingDigest?: string | null;
} = {}): never {
  return {
    query: async (sql: string) => {
      if (sql.includes("tarball_digest") && sql.includes("from releases")) {
        return {
          rows: options.existingDigest
            ? [
                {
                  id: "11111111-1111-1111-1111-111111111111",
                  tarball_digest: options.existingDigest,
                  status: "pending",
                },
              ]
            : [],
        };
      }
      if (sql.includes("select exists")) {
        return { rows: [{ has_release: options.owned ?? false }] };
      }
      if (sql.includes("select * from releases")) {
        return { rows: options.release ? [options.release] : [] };
      }
      return { rows: [] };
    },
  } as never;
}

function integrityFor(buffer: Buffer): string {
  return `sha512-${createHash("sha512").update(buffer).digest("base64")}`;
}

function shasumFor(buffer: Buffer): string {
  return createHash("sha1").update(buffer).digest("hex");
}

function publishPayload() {
  const manifest = {
    name: "@veripack/safe-package",
    version: "1.0.0",
    scripts: {},
    trust: { intent: "Add a greeting helper." },
    dist: {
      integrity: integrityFor(TARBALL),
      shasum: shasumFor(TARBALL),
      tarball:
        "http://localhost:4874/@veripack/safe-package/-/safe-package-1.0.0.tgz",
    },
  };

  return {
    _id: "@veripack/safe-package",
    name: "@veripack/safe-package",
    "dist-tags": { latest: "1.0.0" },
    versions: { "1.0.0": manifest },
    _attachments: {
      "@veripack/safe-package-1.0.0.tgz": {
        content_type: "application/octet-stream",
        data: TARBALL.toString("base64"),
        length: TARBALL.length,
      },
    },
  };
}

const apps: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

async function makeApp(options: {
  pool?: unknown;
  storage?: unknown;
  boss?: unknown;
  setDistTag?: ReturnType<typeof vi.fn>;
  deleteDistTag?: ReturnType<typeof vi.fn>;
} = {}): Promise<FastifyInstance> {
  const app = await buildServer({
    config: testConfig(),
    pool: options.pool ?? makePool(),
    storage: options.storage ?? {},
    verdaccio: {
      setDistTag: options.setDistTag ?? vi.fn(async () => undefined),
      deleteDistTag: options.deleteDistTag ?? vi.fn(async () => undefined),
      isReachable: async () => true,
    },
    boss: options.boss ?? {},
    lifecycle: {},
  } as never);
  apps.push(app);
  return app;
}

const publisher = { authorization: "Bearer publisher-secret" };

describe("dist-tag routes", () => {
  it("sets a tag only for an installable release", async () => {
    const setDistTag = vi.fn(async () => undefined);
    const app = await makeApp({
      pool: makePool({ release: makeRelease() }),
      setDistTag,
    });

    const response = await app.inject({
      method: "PUT",
      url: "/@team/pkg/-/dist-tags/next",
      headers: publisher,
      payload: { version: "1.0.0" },
    });

    expect(response.statusCode).toBe(200);
    expect(setDistTag).toHaveBeenCalledWith("@team/pkg", "next", "1.0.0");
    expect(response.json()).toEqual({
      ok: true,
      package: "@team/pkg",
      tag: "next",
      version: "1.0.0",
      mirrored: true,
    });
  });

  it("refuses a tag for an approved release whose replay failed", async () => {
    const setDistTag = vi.fn(async () => undefined);
    const app = await makeApp({
      pool: makePool({
        release: makeRelease({ replay_state: "failed" }),
      }),
      setDistTag,
    });

    const response = await app.inject({
      method: "PUT",
      url: "/@team/pkg/-/dist-tags/next",
      headers: publisher,
      payload: { version: "1.0.0" },
    });

    expect(response.statusCode).toBe(409);
    expect(setDistTag).not.toHaveBeenCalled();
  });

  it("deletes a tag for an owned package", async () => {
    const deleteDistTag = vi.fn(async () => undefined);
    const app = await makeApp({
      pool: makePool({ owned: true }),
      deleteDistTag,
    });

    const response = await app.inject({
      method: "DELETE",
      url: "/@team/pkg/-/dist-tags/next",
      headers: publisher,
    });

    expect(response.statusCode).toBe(200);
    expect(deleteDistTag).toHaveBeenCalledWith("@team/pkg", "next");
  });

  it("refuses to delete a tag on a package with no installable release", async () => {
    const deleteDistTag = vi.fn(async () => undefined);
    const app = await makeApp({
      pool: makePool({ owned: false }),
      deleteDistTag,
    });

    const response = await app.inject({
      method: "DELETE",
      url: "/@team/pkg/-/dist-tags/next",
      headers: publisher,
    });

    expect(response.statusCode).toBe(409);
    expect(deleteDistTag).not.toHaveBeenCalled();
  });

  it("requires publisher authentication", async () => {
    const app = await makeApp();

    const response = await app.inject({
      method: "PUT",
      url: "/@team/pkg/-/dist-tags/next",
      payload: { version: "1.0.0" },
    });

    expect(response.statusCode).toBe(401);
  });
});

function makePublishPool(release: ReleaseRow, claim: boolean): never {
  const client = {
    query: async (sql: string) => {
      if (sql.includes("insert into releases")) return { rows: [release] };
      return { rows: [] };
    },
    release: () => undefined,
  };

  return {
    query: async (sql: string) => {
      if (sql.includes("select tarball_digest from releases")) return { rows: [] };
      if (sql.includes("with candidates")) {
        return { rows: claim ? [{ release_id: release.id }] : [] };
      }
      return { rows: [] };
    },
    connect: async () => client,
  } as never;
}

describe("publish route", () => {
  it("stores a new release as pending and enqueues exactly one audit job", async () => {
    const release = makeRelease({ status: "pending", replay_state: "not_started" });
    const storage = {
      putTarball: vi.fn(async () => undefined),
      putJson: vi.fn(async () => undefined),
      deleteObject: vi.fn(async () => undefined),
    };
    const send = vi.fn(async () => "job-1");
    const app = await makeApp({
      pool: makePublishPool(release, true),
      storage,
      boss: { send },
    });

    const response = await app.inject({
      method: "PUT",
      url: "/@veripack/safe-package",
      headers: publisher,
      payload: publishPayload(),
    });

    expect(response.statusCode).toBe(201);
    expect(response.json()).toMatchObject({
      ok: true,
      id: release.id,
      package: release.package_name,
      version: release.version,
      status: "pending",
    });
    expect(storage.putTarball).toHaveBeenCalledWith(
      expect.any(String),
      TARBALL,
    );
    expect(storage.putJson).toHaveBeenCalled();
    expect(send).toHaveBeenCalledWith(
      "veripack-audit",
      { releaseId: release.id },
      { retryLimit: 3, retryDelay: 2 },
    );
  });

  it("rejects a version that already exists with different content", async () => {
    const app = await makeApp({
      pool: makePool({ existingDigest: "already-stored" }),
    });

    const response = await app.inject({
      method: "PUT",
      url: "/@veripack/safe-package",
      headers: publisher,
      payload: publishPayload(),
    });

    expect(response.statusCode).toBe(409);
    expect(response.json().error).toMatch(/already exists/i);
  });

  it("returns the existing release for an idempotent republish", async () => {
    const digest = createHash("sha256").update(TARBALL).digest("hex");
    const app = await makeApp({
      pool: makePool({ existingDigest: digest }),
    });

    const response = await app.inject({
      method: "PUT",
      url: "/@veripack/safe-package",
      headers: publisher,
      payload: publishPayload(),
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      ok: true,
      id: "11111111-1111-1111-1111-111111111111",
      status: "pending",
      auditId: null,
      idempotent: true,
    });
  });

  it("rejects a malformed publish payload before storing anything", async () => {
    const app = await makeApp();

    const response = await app.inject({
      method: "PUT",
      url: "/@veripack/safe-package",
      headers: publisher,
      payload: {},
    });

    expect(response.statusCode).toBe(400);
  });

  it("requires publisher authentication", async () => {
    const app = await makeApp();

    const response = await app.inject({
      method: "PUT",
      url: "/@veripack/safe-package",
      payload: publishPayload(),
    });

    expect(response.statusCode).toBe(401);
  });
});

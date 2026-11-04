import { afterEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { config as defaultConfig } from "../config.js";
import type { ReleaseRow } from "../releases.js";
import { buildServer } from "../server.js";
import { filterPackument } from "./read.js";

function packument() {
  return {
    name: "@veripack/example",
    versions: {
      "1.0.0": {
        dist: {
          tarball: "https://upstream.test/@veripack/example/-/example-1.0.0.tgz",
        },
      },
      "2.0.0": {
        dist: {
          tarball: "https://upstream.test/@veripack/example/-/example-2.0.0.tgz",
        },
      },
    },
    "dist-tags": { latest: "2.0.0", next: "2.0.0" },
    time: {
      created: "2026-01-01T00:00:00.000Z",
      modified: "2026-02-01T00:00:00.000Z",
      "1.0.0": "2026-01-01T00:00:00.000Z",
      "2.0.0": "2026-02-01T00:00:00.000Z",
    },
  };
}

describe("filterPackument", () => {
  it("hides a yanked latest version and repoints latest to the highest remaining version", () => {
    const doc = packument();

    const changed = filterPackument(
      doc,
      new Map([["2.0.0", { status: "yanked", replay_state: "succeeded" }]]),
      "https://registry.test",
    );

    expect(changed).toBe(true);
    expect(Object.keys(doc.versions)).toEqual(["1.0.0"]);
    expect(doc["dist-tags"]).toEqual({ latest: "1.0.0" });
    expect(doc.time).toEqual({
      created: "2026-01-01T00:00:00.000Z",
      modified: "2026-02-01T00:00:00.000Z",
      "1.0.0": "2026-01-01T00:00:00.000Z",
    });
  });

  it("leaves no latest tag when every version is hidden", () => {
    const doc = packument();

    filterPackument(
      doc,
      new Map([
        ["1.0.0", { status: "quarantined", replay_state: "succeeded" }],
        ["2.0.0", { status: "yanked", replay_state: "succeeded" }],
      ]),
      "https://registry.test",
    );

    expect(doc.versions).toEqual({});
    expect(doc["dist-tags"]).toEqual({});
  });
});

const apps: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

function rejectedRelease(): ReleaseRow {
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
    status: "rejected",
    replay_state: "not_started",
    replay_job_id: null,
    replay_started_at: null,
    publisher: "publisher",
    intent: "Add a helper.",
    manifest: {},
    created_at: new Date("2026-01-01T00:00:00.000Z"),
    updated_at: new Date("2026-01-01T00:00:00.000Z"),
  };
}

describe("tarball access", () => {
  it("fails closed with 503 when the install event cannot be written", async () => {
    const approved: ReleaseRow = {
      ...rejectedRelease(),
      status: "approved",
      replay_state: "succeeded",
    };
    const app = await buildServer({
      config: {
        ...defaultConfig,
        LOG_LEVEL: "silent",
        AUTH_MODE: "static",
        VERIPACK_TOKEN: "publisher-secret",
        DEFAULT_PUBLISHER: "publisher",
        ORG_ID: "org-a",
        RATE_LIMIT_BACKEND: "memory",
      },
      pool: {
        query: async (sql: string) => {
          if (sql.includes("insert into install_events")) {
            throw new Error("database is down");
          }
          if (sql.includes("from releases")) return { rows: [approved] };
          return { rows: [{ blocked: false }] };
        },
      },
      storage: { exists: async () => true },
      verdaccio: { isReachable: async () => true },
      boss: {},
      lifecycle: {},
    } as never);
    apps.push(app);

    const response = await app.inject({
      method: "GET",
      url: "/@team/pkg/-/pkg-1.0.0.tgz",
      headers: { authorization: "Bearer publisher-secret" },
    });

    expect(response.statusCode).toBe(503);
    expect(response.json().error).toContain("Install event");
  });

  it("refuses a tarball whose release is not downloadable", async () => {
    const app = await buildServer({
      config: {
        ...defaultConfig,
        LOG_LEVEL: "silent",
        AUTH_MODE: "static",
        VERIPACK_TOKEN: "publisher-secret",
        DEFAULT_PUBLISHER: "publisher",
        ORG_ID: "org-a",
        RATE_LIMIT_BACKEND: "memory",
      },
      pool: { query: async () => ({ rows: [rejectedRelease()] }) },
      storage: {},
      verdaccio: { isReachable: async () => true },
      boss: {},
      lifecycle: {},
    } as never);
    apps.push(app);

    const response = await app.inject({
      method: "GET",
      url: "/@team/pkg/-/pkg-1.0.0.tgz",
      headers: { authorization: "Bearer publisher-secret" },
    });

    expect(response.statusCode).toBe(404);
    expect(response.json().error).toContain("rejected");
  });

  it("leaves latest absent when only prereleases are visible", () => {
    const doc = {
      name: "@veripack/example",
      versions: {
        "2.0.0-beta.1": {
          dist: {
            tarball:
              "https://upstream.test/@veripack/example/-/example-2.0.0-beta.1.tgz",
          },
        },
      },
      "dist-tags": { latest: "2.0.0-beta.1", next: "2.0.0-beta.1" },
      time: {},
    };

    filterPackument(doc, new Map(), "https://registry.test", {
      next: "2.0.0-beta.1",
    });

    expect(doc["dist-tags"]).toEqual({ next: "2.0.0-beta.1" });
  });
});

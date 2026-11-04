import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as tar from "tar";
import { afterEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { config as defaultConfig, type Config } from "../config.js";
import { buildServer } from "../server.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

async function buildTarball(): Promise<Buffer> {
  const directory = await mkdtemp(join(tmpdir(), "veripack-preflight-"));
  temporaryDirectories.push(directory);
  await mkdir(join(directory, "package"), { recursive: true });
  await writeFile(
    join(directory, "package", "package.json"),
    JSON.stringify({ name: "@team/pkg", version: "1.0.0" }),
  );
  await writeFile(
    join(directory, "package", "index.js"),
    "export const value = 1;\n",
  );

  const chunks: Buffer[] = [];
  const stream = tar.c(
    { gzip: true, cwd: directory, portable: true },
    ["package"],
  );
  stream.on("data", (chunk: Buffer) => chunks.push(chunk));
  await new Promise<void>((resolve, reject) => {
    stream.on("end", resolve);
    stream.on("error", reject);
  });
  return Buffer.concat(chunks);
}

function testConfig(overrides: Partial<Config> = {}): Config {
  return {
    ...defaultConfig,
    LOG_LEVEL: "silent",
    AUTH_MODE: "static",
    VERIPACK_TOKEN: "publisher-secret",
    ADMIN_TOKEN: "admin-secret",
    DEFAULT_PUBLISHER: "publisher",
    ORG_ID: "org-a",
    RATE_LIMIT_BACKEND: "memory",
    ...overrides,
  };
}

function makePool(): never {
  return {
    query: async (sql: string) => {
      if (sql.includes("select count(*)::text")) {
        return { rows: [{ count: "0" }] };
      }
      return { rows: [] };
    },
  } as never;
}

const apps: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

async function makeApp(config: Config = testConfig()): Promise<FastifyInstance> {
  const app = await buildServer({
    config,
    pool: makePool(),
    storage: { getBuffer: async () => Buffer.alloc(0) },
    verdaccio: { isReachable: async () => true },
    boss: {},
    lifecycle: {},
  } as never);
  apps.push(app);
  return app;
}

const publisher = { authorization: "Bearer publisher-secret" };

async function body(overrides: Record<string, unknown> = {}) {
  const tarball = await buildTarball();
  return {
    packageName: "@team/pkg",
    version: "1.0.0",
    manifest: {
      name: "@team/pkg",
      version: "1.0.0",
      trust: { intent: "Add a helper." },
    },
    tarballBase64: tarball.toString("base64"),
    ...overrides,
  };
}

describe("preflight route", () => {
  it("returns the audit result for a valid publisher request", async () => {
    const app = await makeApp();

    const response = await app.inject({
      method: "POST",
      url: "/-/veripack/preflight",
      headers: publisher,
      payload: await body(),
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      mode: "static",
      packageName: "@team/pkg",
      version: "1.0.0",
      sandbox: null,
      result: {
        policyVersion: "v1-default-1",
        changeSet: { engine: "static" },
      },
    });
  });

  it("rejects a request missing the tarball", async () => {
    const app = await makeApp();

    const response = await app.inject({
      method: "POST",
      url: "/-/veripack/preflight",
      headers: publisher,
      payload: await body({ tarballBase64: "" }),
    });

    expect(response.statusCode).toBe(400);
  });

  it("refuses a sandbox request when sandbox execution is disabled", async () => {
    const app = await makeApp(testConfig({ SANDBOX_MODE: "disabled" }));

    const response = await app.inject({
      method: "POST",
      url: "/-/veripack/preflight",
      headers: publisher,
      payload: await body({ sandbox: true }),
    });

    expect(response.statusCode).toBe(409);
    expect(response.json().error).toMatch(/SANDBOX_MODE is disabled/);
  });

  it("requires publisher authentication", async () => {
    const app = await makeApp();

    const response = await app.inject({
      method: "POST",
      url: "/-/veripack/preflight",
      payload: await body(),
    });

    expect(response.statusCode).toBe(401);
  });
});

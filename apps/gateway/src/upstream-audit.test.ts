import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as tar from "tar";
import { afterEach, describe, expect, it } from "vitest";
import { config as defaultConfig } from "./config.js";
import { auditUpstreamTarball } from "./upstream-audit.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true }),
    ),
  );
});

async function safeTarball(): Promise<Buffer> {
  const directory = await mkdtemp(join(tmpdir(), "veripack-upstream-test-"));
  temporaryDirectories.push(directory);
  await mkdir(join(directory, "package"), { recursive: true });
  await writeFile(
    join(directory, "package", "package.json"),
    JSON.stringify({ name: "left-pad", version: "1.0.0" }),
  );
  await writeFile(join(directory, "package", "index.js"), "module.exports = 1;\n");
  const chunks: Buffer[] = [];
  const stream = tar.c(
    { cwd: directory, gzip: true, portable: true },
    ["package"],
  );
  stream.on("data", (chunk: Buffer) => chunks.push(chunk));
  await new Promise<void>((resolve, reject) => {
    stream.on("end", resolve);
    stream.on("error", reject);
  });
  return Buffer.concat(chunks);
}

describe("upstream release auditing", () => {
  it("audits a public tarball and persists structured evidence", async () => {
    const queries: string[] = [];
    const db = {
      query: async (sql: string) => {
        queries.push(sql);
        if (sql.includes("from upstream_audits")) return { rows: [] };
        if (sql.includes("from audit_cache")) return { rows: [] };
        if (sql.includes("active_policy_versions")) return { rows: [] };
        if (sql.includes("from policy_versions")) return { rows: [] };
        return { rows: [] };
      },
    } as never;

    const result = await auditUpstreamTarball(
      db,
      "left-pad",
      "1.0.0",
      await safeTarball(),
      { ...defaultConfig, ORG_ID: "org-a" },
    );

    expect(result.status).toBe("audited");
    expect(result.changeSet.engine).toBe("static");
    expect(queries.some((sql) => sql.includes("insert into upstream_audits"))).toBe(true);
  });
});

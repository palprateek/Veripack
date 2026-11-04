import { createHash } from "node:crypto";
import { readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { config } from "../config.js";
import { createDb } from "../db.js";
import { Storage } from "../storage.js";
import {
  buildInventoryManifest,
  verifyInventoryManifest,
  type InventoryManifest,
} from "./backup.js";

function redact(value: string): string {
  let redacted = value.replaceAll(config.DATABASE_URL, "<REDACTED_DATABASE_URL>");
  const restoreUrl = process.env.RESTORE_DATABASE_URL?.trim();
  if (restoreUrl) {
    redacted = redacted.replaceAll(restoreUrl, "<REDACTED_RESTORE_DATABASE_URL>");
  }
  return redacted.replace(/(postgres(?:ql)?:\/\/[^:/]+:)[^@]+@/gi, "$1<REDACTED>@");
}

function run(command: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) return resolve(Buffer.concat(stdout).toString("utf8"));
      reject(
        new Error(
          redact(
            `${command} exited with ${code}: ${Buffer.concat(stderr)
              .toString("utf8")
              .slice(0, 1_000)}`,
          ),
        ),
      );
    });
  });
}

async function main(): Promise<void> {
  const restoreUrl = process.env.RESTORE_DATABASE_URL?.trim() ?? "";
  const command = process.argv[2] ?? "backup";
  if (command === "restore-check" && !restoreUrl) {
    throw new Error("RESTORE_DATABASE_URL must point to a disposable scratch database.");
  }
  if (restoreUrl && restoreUrl === config.DATABASE_URL) {
    throw new Error("RESTORE_DATABASE_URL must not equal DATABASE_URL.");
  }

  const stamp = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
  const file = join(tmpdir(), `veripack-${stamp}.dump`);
  try {
    await run("pg_dump", [
      "--format=custom",
      "--no-owner",
      "--no-privileges",
      "--file",
      file,
      config.DATABASE_URL,
    ]);
    await run("pg_restore", ["--list", file]);
    const dump = await readFile(file);
    const digest = createHash("sha256").update(dump).digest("hex");
    const storage = await Storage.create(config);
    const key = `${config.BACKUP_S3_PREFIX.replace(/\/+$/, "")}/${stamp}-${digest.slice(0, 16)}.dump`;
    await storage.putBuffer(key, dump, "application/octet-stream");
    await storage.putJson(`${key}.json`, {
      createdAt: new Date().toISOString(),
      database: "veripack",
      sha256: digest,
      bytes: dump.length,
      key,
    });

    // Inventory manifest: every object the database references, with size
    // and SHA-256, verified on restore instead of counting rows.
    const manifestPool = createDb(config.DATABASE_URL, {
      ssl: config.DATABASE_SSL,
      rejectUnauthorized: config.DATABASE_SSL_REJECT_UNAUTHORIZED,
    });
    let manifest: InventoryManifest;
    try {
      manifest = await buildInventoryManifest(manifestPool, storage, {
        key,
        sha256: digest,
        bytes: dump.length,
      });
    } finally {
      await manifestPool.end();
    }
    await storage.putJson(`${key}.manifest.json`, manifest);

    if (command === "restore-check") {
      await run("pg_restore", [
        "--clean",
        "--if-exists",
        "--exit-on-error",
        "--no-owner",
        "--no-privileges",
        "--dbname",
        restoreUrl,
        file,
      ]);
      const verification = await run("psql", [
        restoreUrl,
        "-v",
        "ON_ERROR_STOP=1",
        "-tAc",
        "select (select count(*) from schema_migrations) > 0 and (select count(*) from releases) >= 0 and (select count(*) from audits) >= 0",
      ]);
      if (verification.trim() !== "t") {
        throw new Error("Restored database verification query returned false.");
      }
      const verified = await verifyInventoryManifest(storage, manifest);
      console.log(
        JSON.stringify({
          ok: true,
          key,
          sha256: digest,
          restored: true,
          verifiedObjects: verified.verified,
        }),
      );
    } else {
      console.log(JSON.stringify({ ok: true, key, sha256: digest, restored: false }));
    }
  } finally {
    await rm(file, { force: true });
  }
}

main().catch((error) => {
  console.error(redact(error instanceof Error ? error.message : String(error)));
  process.exitCode = 1;
});

import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as tar from "tar";
import type { Config } from "./config.js";
import { readArchive } from "./audit/archive.js";

export interface SandboxResult {
  enabled: boolean;
  runtime: string | null;
  image: string | null;
  exitCode: number | null;
  signal: string | null;
  timedOut: boolean;
  stdout: string;
  stderr: string;
  durationMs: number;
}

const RUNNER = `
const fs = require("node:fs");
const path = require("node:path");
const { pathToFileURL } = require("node:url");

(async () => {
  const root = "/input/package";
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  const entry = typeof manifest.main === "string" ? manifest.main : "index.js";
  const target = path.resolve(root, entry);
  if (!target.startsWith(root + path.sep) && target !== root) {
    throw new Error("Package entrypoint escapes the extracted package root.");
  }
  if (fs.existsSync(target)) {
    await import(pathToFileURL(target).href);
    process.stdout.write(JSON.stringify({ entrypoint: entry, loaded: true }) + "\\n");
  } else {
    process.stdout.write(JSON.stringify({ entrypoint: entry, loaded: false }) + "\\n");
  }
})().catch((error) => {
  process.stderr.write(error instanceof Error ? error.stack || error.message : String(error));
  process.exitCode = 1;
});
`;

function trimOutput(value: string, limit: number): string {
  return value.length <= limit ? value : `${value.slice(0, limit)}\n[…output truncated]`;
}

export async function runSandbox(
  tarball: Buffer,
  config: Pick<
    Config,
    | "SANDBOX_MODE"
    | "SANDBOX_IMAGE"
    | "SANDBOX_TIMEOUT_MS"
    | "SANDBOX_MEMORY_MB"
    | "SANDBOX_CPUS"
    | "SANDBOX_MAX_OUTPUT_BYTES"
  >,
): Promise<SandboxResult> {
  if (config.SANDBOX_MODE === "disabled") {
    return {
      enabled: false,
      runtime: null,
      image: null,
      exitCode: null,
      signal: null,
      timedOut: false,
      stdout: "",
      stderr: "",
      durationMs: 0,
    };
  }

  const inventory = await readArchive(tarball);
  if (!inventory.packageJson) {
    throw new Error("Sandbox input is missing a valid package.json.");
  }
  if (inventory.files.some((file) => file.type !== "file")) {
    throw new Error("Sandbox refuses archives containing links or special files.");
  }

  const runtime = config.SANDBOX_MODE;
  const directory = await mkdtemp(join(tmpdir(), "veripack-sandbox-"));
  const archivePath = join(directory, "package.tgz");
  const runnerPath = join(directory, "runner.cjs");
  const packageDirectory = join(directory, "package");
  try {
    await mkdir(packageDirectory, { recursive: true, mode: 0o700 });
    await Promise.all([
      writeFile(archivePath, tarball, { mode: 0o400 }),
      writeFile(runnerPath, RUNNER, { mode: 0o400 }),
    ]);
    await tar.x({
      file: archivePath,
      cwd: packageDirectory,
      strip: 1,
      strict: true,
      preservePaths: false,
      noMtime: true,
    });
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  }

  const started = Date.now();
  const args = [
    "run",
    "--rm",
    "--network=none",
    "--read-only",
    "--user=65532:65532",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    "--pids-limit=128",
    `--memory=${config.SANDBOX_MEMORY_MB}m`,
    `--cpus=${config.SANDBOX_CPUS}`,
    "--tmpfs=/tmp:rw,noexec,nosuid,size=64m",
    "-v",
    `${directory}:/input:ro`,
    config.SANDBOX_IMAGE,
    "node",
    "/input/runner.cjs",
  ];

  try {
    const result = await new Promise<{
      exitCode: number | null;
      signal: string | null;
      timedOut: boolean;
      stdout: string;
      stderr: string;
    }>((resolve, reject) => {
      const child = spawn(runtime, args, { stdio: ["ignore", "pipe", "pipe"] });
      let stdout = "";
      let stderr = "";
      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        child.kill("SIGKILL");
      }, config.SANDBOX_TIMEOUT_MS);
      child.stdout.on("data", (chunk: Buffer) => {
        if (stdout.length < config.SANDBOX_MAX_OUTPUT_BYTES) {
          stdout += chunk.toString("utf8").slice(0, config.SANDBOX_MAX_OUTPUT_BYTES - stdout.length);
        }
      });
      child.stderr.on("data", (chunk: Buffer) => {
        if (stderr.length < config.SANDBOX_MAX_OUTPUT_BYTES) {
          stderr += chunk.toString("utf8").slice(0, config.SANDBOX_MAX_OUTPUT_BYTES - stderr.length);
        }
      });
      child.on("error", (error) => {
        clearTimeout(timer);
        reject(error);
      });
      child.on("close", (exitCode, signal) => {
        clearTimeout(timer);
        resolve({
          exitCode,
          signal,
          timedOut,
          stdout: trimOutput(stdout, config.SANDBOX_MAX_OUTPUT_BYTES),
          stderr: trimOutput(stderr, config.SANDBOX_MAX_OUTPUT_BYTES),
        });
      });
    });

    return {
      enabled: true,
      runtime,
      image: config.SANDBOX_IMAGE,
      ...result,
      durationMs: Date.now() - started,
    };
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

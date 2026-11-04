#!/usr/bin/env node
/**
 * Staging exit checks for a deployed Veripack stack. Read-only probes plus
 * optional sample publish/install when SAMPLE_PACKAGE_DIR is set.
 *
 * Env:
 *   VERIPACK_REGISTRY_URL  gateway URL (default http://localhost:4874)
 *   VERIPACK_ADMIN_TOKEN   admin token for identity/blocklist checks
 *   VERIPACK_REGISTRY_TOKEN publisher token for sample publish/install
 *   SAMPLE_PACKAGE_DIR     optional package directory to publish + install
 */
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const registry = (process.env.VERIPACK_REGISTRY_URL || "http://localhost:4874").replace(/\/+$/, "");
const adminToken = process.env.VERIPACK_ADMIN_TOKEN || "";
const publisherToken = process.env.VERIPACK_REGISTRY_TOKEN || "";

let failures = 0;

function check(name, ok, detail = "") {
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail ? ` — ${detail}` : ""}`);
  if (!ok) failures += 1;
}

async function get(path, token) {
  const response = await fetch(`${registry}${path}`, {
    headers: token ? { authorization: `Bearer ${token}` } : {},
    signal: AbortSignal.timeout(10_000),
  });
  return response;
}

function run(command, args, options) {
  return new Promise((resolvePromise) => {
    const child = spawn(command, args, { ...options, stdio: "pipe" });
    let out = "";
    child.stdout.on("data", (chunk) => (out += chunk));
    child.stderr.on("data", (chunk) => (out += chunk));
    child.on("close", (code) => resolvePromise({ code, out }));
    child.on("error", (error) => resolvePromise({ code: -1, out: String(error) }));
  });
}

const readyz = await get("/readyz").catch(() => null);
check("gateway readyz (db, verdaccio identity auth, worker)", readyz?.ok === true, readyz ? `status ${readyz.status}` : "unreachable");

const livez = await get("/livez").catch(() => null);
check("gateway livez", livez?.ok === true);

if (adminToken) {
  const identity = await get("/admin/verdaccio/identity", adminToken).catch(() => null);
  const identityBody = identity ? await identity.json().catch(() => ({})) : {};
  check(
    "verdaccio active identity configured",
    identity?.ok === true && typeof identityBody.active === "string",
    identityBody.active ?? "",
  );

  const blocklist = await get("/admin/blocklist", adminToken).catch(() => null);
  check("blocklist readable", blocklist?.ok === true);
} else {
  console.log("SKIP admin checks (VERIPACK_ADMIN_TOKEN not set)");
}

if (process.env.SAMPLE_PACKAGE_DIR && publisherToken) {
  const sampleDir = process.env.SAMPLE_PACKAGE_DIR;
  const publish = await run(
    "node",
    [
      new URL("./veripack-cli.mjs", import.meta.url).pathname,
      "publish",
      sampleDir,
      "--intent",
      "staging sample publish",
      "--registry",
      registry,
      "--token",
      publisherToken,
    ],
    {},
  );
  check("sample publish accepted", publish.code === 0, publish.out.trim().split("\n").pop() ?? "");

  const scratch = await mkdtemp(join(tmpdir(), "veripack-staging-install-"));
  try {
    const install = await run(
      "npm",
      ["install", "--ignore-scripts", "--no-audit", "--no-fund"],
      {
        cwd: scratch,
        env: {
          ...process.env,
          npm_config_registry: `${registry}/`,
          npm_config__authToken: publisherToken,
        },
      },
    );
    check("sample install ran", install.code === 0);
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
} else {
  console.log("SKIP sample publish/install (SAMPLE_PACKAGE_DIR or VERIPACK_REGISTRY_TOKEN not set)");
}

console.log(failures === 0 ? "STAGING CHECKS PASSED" : `${failures} check(s) failed`);
process.exitCode = failures === 0 ? 0 : 1;

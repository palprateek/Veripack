#!/usr/bin/env node
import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";

function usage() {
  console.error(`Usage:
  veripack audit <package-directory|package.tgz> [options]
  veripack registry rebuild [--registry <url>] [--token <admin-token>]
  veripack registry identity rotate --identity <a|b> [--registry <url>] [--token <admin-token>]
  veripack registry artifact reupload --release <id> --file <tarball.tgz> [--registry <url>] [--token <admin-token>]
  veripack bypass-check <package-lock.json|pnpm-lock.yaml|bun.lock> [--registry <url>]
  veripack publish <package-directory> --intent <text> [--registry <url>] [--token <token>] [--fail-on <level>]
  veripack run <package[@version]> [--yes] [-- <package-args...>] [--registry <url>] [--token <token>]

Options:
  --registry <url>   Veripack gateway URL (default: VERIPACK_REGISTRY_URL or localhost)
  --token <token>    registry token (default: VERIPACK_REGISTRY_TOKEN)
  --sandbox          explicitly run the configured dynamic sandbox
  --fail-on <level>  block (default), warn, or never
  --json             print machine-readable JSON only
`);
}

function option(args, name, fallback = "") {
  const index = args.indexOf(name);
  return index === -1 ? fallback : args[index + 1] ?? fallback;
}

function has(args, name) {
  return args.includes(name);
}

function run(command, args, options) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, { ...options, stdio: ["ignore", "pipe", "pipe"] });
    const stdout = [];
    const stderr = [];
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.on("error", reject);
    child.on("close", (code, signal) =>
      resolvePromise({
        code,
        signal,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      }),
    );
  });
}

async function packDirectory(directory, temporary) {
  const result = await run("npm", [
    "pack",
    "--ignore-scripts",
    "--json",
    "--pack-destination",
    temporary,
  ], { cwd: directory });
  if (result.code !== 0) {
    throw new Error(result.stderr.trim() || "npm pack failed.");
  }
  let metadata;
  try {
    metadata = JSON.parse(result.stdout);
  } catch {
    throw new Error("npm pack returned invalid JSON metadata.");
  }
  const filename = Array.isArray(metadata) ? metadata[0]?.filename : null;
  if (typeof filename !== "string") throw new Error("npm pack did not return a tarball filename.");
  return join(temporary, filename);
}

async function gatewayPost(path, body, registry, token) {
  const response = await fetch(`${registry}${path}`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
      accept: "application/json",
    },
    body: JSON.stringify(body),
  });
  const payload = await response.json().catch(() => ({ error: "Gateway returned invalid JSON." }));
  if (!response.ok) {
    throw new Error(payload.error || `Gateway request failed (${response.status}).`);
  }
  return payload;
}

function bypassFindings(kind, content, gatewayHost) {
  const findings = [];
  const check = (name, resolved) => {
    try {
      if (new URL(resolved).host !== gatewayHost) {
        findings.push({ packageName: name, resolved });
      }
    } catch {
      // Not a URL (local/path resolution): not a registry bypass.
    }
  };
  if (kind === "npm") {
    const parsed = JSON.parse(content);
    for (const [path, entry] of Object.entries(parsed.packages || {})) {
      if (typeof entry?.resolved === "string") {
        check(entry.name || path.replace(/^.*node_modules\//, ""), entry.resolved);
      }
    }
  } else if (kind === "pnpm") {
    let current = "(unknown)";
    for (const line of content.split("\n")) {
      const pkg = /^\s{2}(\/?[^\s:]+@[^\s:]+):\s*$/.exec(line);
      if (pkg) current = pkg[1].replace(/^\//, "");
      const tarball = /tarball:\s*(\S+)/.exec(line);
      if (tarball) check(current, tarball[1]);
    }
  } else {
    const parsed = JSON.parse(content.replace(/,\s*([}\]])/g, "$1"));
    for (const [name, entries] of Object.entries(parsed.packages || {})) {
      const resolved = Array.isArray(entries)
        ? entries.find((entry) => typeof entry === "string" && /^https?:\/\//.test(entry))
        : undefined;
      if (resolved) check(name, resolved);
    }
  }
  return findings;
}

async function registryCommand(args) {
  const registry = option(args, "--registry", process.env.VERIPACK_REGISTRY_URL || "http://localhost:4874").replace(/\/+$/, "");
  const token = option(args, "--token", process.env.VERIPACK_ADMIN_TOKEN || process.env.VERIPACK_REGISTRY_TOKEN || "");
  if (!token) throw new Error("An admin token is required via --token or VERIPACK_ADMIN_TOKEN.");

  if (args[1] === "rebuild") {
    const report = await gatewayPost("/admin/registry/rebuild", {}, registry, token);
    console.log(JSON.stringify(report, null, 2));
    if (report.unresolved?.length) process.exitCode = 1;
    return;
  }
  if (args[1] === "identity" && args[2] === "rotate") {
    const identity = option(args, "--identity");
    if (!identity) throw new Error("--identity <a|b> is required.");
    const result = await gatewayPost("/admin/verdaccio/identity/rotate", { identity }, registry, token);
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  if (args[1] === "artifact" && args[2] === "reupload") {
    const release = option(args, "--release");
    const file = option(args, "--file");
    if (!release || !file) throw new Error("--release <id> and --file <tarball> are required.");
    const tarballBase64 = (await readFile(resolve(file))).toString("base64");
    const result = await gatewayPost(`/admin/releases/${release}/artifact/reupload`, { tarballBase64 }, registry, token);
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  usage();
  process.exitCode = 2;
}

async function bypassCommand(args) {
  const file = resolve(args[1]);
  const registry = option(args, "--registry", process.env.VERIPACK_REGISTRY_URL || "http://localhost:4874");
  const kind = file.endsWith("package-lock.json")
    ? "npm"
    : file.endsWith("pnpm-lock.yaml")
      ? "pnpm"
      : file.endsWith("bun.lock") || file.endsWith("bun.lockb")
        ? "bun"
        : null;
  if (!kind) throw new Error("Unsupported lockfile. Expected package-lock.json, pnpm-lock.yaml, or bun.lock.");
  const findings = bypassFindings(kind, await readFile(file, "utf8"), new URL(registry).host);
  if (findings.length === 0) {
    console.log("All resolutions went through the gateway.");
    return;
  }
  console.log(`${findings.length} resolution(s) did not go through the gateway:`);
  for (const finding of findings) {
    console.log(`- ${finding.packageName}: ${finding.resolved}`);
  }
}

async function publishCommand(args) {
  const directory = resolve(args[1]);
  const registry = option(args, "--registry", process.env.VERIPACK_REGISTRY_URL || "http://localhost:4874").replace(/\/+$/, "");
  const token = option(args, "--token", process.env.VERIPACK_REGISTRY_TOKEN || "");
  const failOn = option(args, "--fail-on", "block");
  if (!token) throw new Error("A registry token is required via --token or VERIPACK_REGISTRY_TOKEN.");
  if (!existsSync(directory)) throw new Error(`Path does not exist: ${directory}`);

  const manifest = JSON.parse(await readFile(join(directory, "package.json"), "utf8"));
  const intent = option(args, "--intent", "") || manifest.trust?.intent || "";
  if (!intent.trim()) {
    throw new Error("trust.intent is required: pass --intent <text> or set trust.intent in package.json.");
  }

  const temporary = await mkdtemp(join(tmpdir(), "veripack-publish-"));
  try {
    // Stage a copy and write the intent into the packed manifest before
    // hashing, so the audited bytes are exactly the uploaded bytes.
    const staging = join(temporary, "stage");
    await cp(directory, staging, {
      recursive: true,
      filter: (source) =>
        !source.includes("node_modules") && !source.includes(".git"),
    });
    const stagedManifestPath = join(staging, "package.json");
    const stagedManifest = JSON.parse(await readFile(stagedManifestPath, "utf8"));
    stagedManifest.trust = { ...(stagedManifest.trust || {}), intent };
    await writeFile(stagedManifestPath, JSON.stringify(stagedManifest, null, 2) + "\n");

    const tarballPath = await packDirectory(staging, temporary);
    const tarball = await readFile(tarballPath);

    // Preflight is advisory; the gateway audits the uploaded bytes itself.
    const preflight = await fetch(`${registry}/-/veripack/preflight`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify({
        packageName: stagedManifest.name,
        version: stagedManifest.version,
        manifest: stagedManifest,
        tarballBase64: tarball.toString("base64"),
      }),
    });
    const preflightBody = await preflight.json().catch(() => ({ error: "Gateway returned invalid JSON." }));
    if (!preflight.ok) {
      throw new Error(preflightBody.error || `Preflight failed (${preflight.status}).`);
    }
    const result = preflightBody.result || {};
    console.log(`preflight ${stagedManifest.name}@${stagedManifest.version}: ${result.riskTier}/${result.policyResult}/${result.safetyVerdict}`);
    if (failOn === "block" && result.policyResult === "block") {
      throw new Error("Preflight blocked this release; not publishing.");
    }
    if (failOn === "warn" && result.policyResult !== "pass") {
      throw new Error("Preflight did not pass; not publishing.");
    }

    const version = stagedManifest.version;
    const integrity = `sha512-${createHash("sha512").update(tarball).digest("base64")}`;
    const shasum = createHash("sha1").update(tarball).digest("hex");
    const baseName = stagedManifest.name.startsWith("@")
      ? stagedManifest.name.slice(stagedManifest.name.indexOf("/") + 1)
      : stagedManifest.name;
    const filename = `${baseName}-${version}.tgz`;
    const publishManifest = {
      ...stagedManifest,
      dist: {
        integrity,
        shasum,
        tarball: `${registry}/${stagedManifest.name}/-/${filename}`,
      },
    };
    const payload = {
      _id: stagedManifest.name,
      name: stagedManifest.name,
      "dist-tags": { latest: version },
      versions: { [version]: publishManifest },
      _attachments: {
        [filename]: {
          content_type: "application/octet-stream",
          data: tarball.toString("base64"),
          length: tarball.length,
        },
      },
    };
    const packagePath = stagedManifest.name.split("/").map(encodeURIComponent).join("/");
    const response = await fetch(`${registry}/${packagePath}`, {
      method: "PUT",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify(payload),
    });
    const body = await response.json().catch(() => ({ error: "Gateway returned invalid JSON." }));
    if (!response.ok) {
      throw new Error(body.error || `Publish failed (${response.status}).`);
    }
    console.log(JSON.stringify(body, null, 2));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

async function runCommand(args) {
  const spec = args[1];
  const registry = option(args, "--registry", process.env.VERIPACK_REGISTRY_URL || "http://localhost:4874").replace(/\/+$/, "");
  const token = option(args, "--token", process.env.VERIPACK_REGISTRY_TOKEN || "");
  if (!token) throw new Error("A registry token is required via --token or VERIPACK_REGISTRY_TOKEN.");
  const separator = args.indexOf("--");
  const packageArgs = separator === -1 ? [] : args.slice(separator + 1);
  const at = spec.lastIndexOf("@");
  const name = at > 0 ? spec.slice(0, at) : spec;
  const version = at > 0 ? spec.slice(at + 1) : "";

  const statusResponse = await fetch(
    `${registry}/-/veripack/audit-status?package=${encodeURIComponent(name)}${version ? `&version=${encodeURIComponent(version)}` : ""}`,
    { headers: { authorization: `Bearer ${token}`, accept: "application/json" } },
  );
  const status = await statusResponse.json().catch(() => ({}));
  if (!statusResponse.ok) throw new Error(status.error || `Audit status failed (${statusResponse.status}).`);

  console.log(`${status.packageName}@${status.version ?? version ?? "latest"} [${status.source}] status=${status.status} risk=${status.riskTier ?? "n/a"} policy=${status.policyResult ?? "n/a"}`);
  if (status.summary) console.log(status.summary);

  if (status.policyResult === "block" || ["rejected", "quarantined"].includes(status.status)) {
    throw new Error("This release is blocked by the registry gate and will not be run.");
  }
  const needsConfirm = status.status === "pending" || status.policyResult === "warn";
  if (needsConfirm && !has(args, "--yes")) {
    const { createInterface } = await import("node:readline");
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    const answer = await new Promise((resolvePromise) =>
      rl.question("This release is not fully approved. Run anyway? [y/N] ", resolvePromise),
    );
    rl.close();
    if (!/^y(es)?$/i.test(String(answer).trim())) {
      console.log("Aborted.");
      return;
    }
  }

  const temporary = await mkdtemp(join(tmpdir(), "veripack-run-"));
  try {
    const host = new URL(registry).host;
    const npmrc = join(temporary, ".npmrc");
    await writeFile(
      npmrc,
      `registry=${registry}/\n//${host}/:_authToken=${token}\n`,
    );
    const result = await run("npx", ["--yes", "--registry", `${registry}/`, "--userconfig", npmrc, spec, ...packageArgs], {
      cwd: process.cwd(),
    });
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
    process.exitCode = typeof result.code === "number" ? result.code : 0;
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

async function main() {
  const args = process.argv.slice(2);
  if (args[0] === "run" && args[1]) {
    await runCommand(args);
    return;
  }
  if (args[0] === "publish" && args[1]) {
    await publishCommand(args);
    return;
  }
  if (args[0] === "registry") {
    await registryCommand(args);
    return;
  }
  if (args[0] === "bypass-check" && args[1]) {
    await bypassCommand(args);
    return;
  }
  if (args[0] !== "audit" || !args[1]) {
    usage();
    process.exitCode = 2;
    return;
  }

  const target = resolve(args[1]);
  const registry = option(args, "--registry", process.env.VERIPACK_REGISTRY_URL || "http://localhost:4874").replace(/\/+$/, "");
  const token = option(args, "--token", process.env.VERIPACK_REGISTRY_TOKEN || "");
  const json = has(args, "--json");
  const sandbox = has(args, "--sandbox");
  const failOn = option(args, "--fail-on", "block");
  if (!token) throw new Error("A registry token is required via --token or VERIPACK_REGISTRY_TOKEN.");
  if (!existsSync(target)) throw new Error(`Path does not exist: ${target}`);

  const temporary = await mkdtemp(join(tmpdir(), "veripack-preflight-"));
  try {
    let manifest;
    if (target.toLowerCase().endsWith(".tgz")) {
      const extracted = join(temporary, "package");
      const extractedResult = await run("tar", ["-xzf", target, "-C", temporary]);
      if (extractedResult.code !== 0) throw new Error(extractedResult.stderr.trim() || "Could not extract the tarball.");
      manifest = JSON.parse(await readFile(join(extracted, "package.json"), "utf8"));
    } else {
      manifest = JSON.parse(await readFile(join(target, "package.json"), "utf8"));
    }
    const tarballPath = target.toLowerCase().endsWith(".tgz")
      ? target
      : await packDirectory(target, temporary);
    const tarball = (await readFile(tarballPath)).toString("base64");
    const response = await fetch(`${registry}/-/veripack/preflight`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify({
        packageName: manifest.name,
        version: manifest.version,
        manifest,
        tarballBase64: tarball,
        sandbox,
      }),
    });
    const body = await response.json().catch(() => ({ error: "Gateway returned invalid JSON." }));
    if (json) {
      console.log(JSON.stringify(body, null, 2));
    } else if (!response.ok) {
      console.error(body.error || `Preflight failed (${response.status}).`);
    } else {
      const result = body.result || {};
      console.log(`${body.packageName}@${body.version}: ${result.riskTier}/${result.policyResult}/${result.safetyVerdict}`);
      console.log(result.summary || "No summary returned.");
      for (const signal of result.signals || []) {
        console.log(`- [${signal.severity}] ${signal.type}: ${signal.message}`);
      }
    }
    if (!response.ok) process.exitCode = 1;
    const result = body.result || {};
    if (failOn === "warn" && result.policyResult !== "pass") process.exitCode = 1;
    if (failOn === "block" && result.policyResult === "block") process.exitCode = 1;
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});

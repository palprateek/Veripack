import { execFileSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const GATEWAY = process.env.PUBLIC_REGISTRY_URL ?? "http://localhost:4874";
const REGISTRY_TOKEN = process.env.REGISTRY_TOKEN ?? "dev-token";
const ADMIN_TOKEN = process.env.ADMIN_TOKEN ?? "admin-token";
const RUN_NUMBER = Date.now() % 900_000_000;
const RUN_VERSION = `1.0.${RUN_NUMBER}`;
const FOLLOWUP_VERSION = `1.0.${RUN_NUMBER + 1}`;

function log(message) {
  console.log(`\n=== ${message}`);
}

function runNpm(args, cwd) {
  execFileSync("npm", args, {
    cwd,
    stdio: "inherit",
    env: {
      ...process.env,
      npm_config_registry: GATEWAY,
      npm_config_audit: "false",
      npm_config_fund: "false",
    },
  });
}

async function admin(path, init = {}) {
  const response = await fetch(`${GATEWAY}${path}`, {
    ...init,
    headers: {
      authorization: `Bearer ${ADMIN_TOKEN}`,
      accept: "application/json",
      ...(init.headers ?? {}),
    },
  });

  const text = await response.text();
  let body;
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    body = { error: text };
  }

  if (!response.ok) {
    throw new Error(
      `Admin request ${init.method ?? "GET"} ${path} failed (${response.status}): ${
        body.error ?? text
      }`,
    );
  }

  return body;
}

async function waitForStatus(packageName, version, expected, timeoutMs = 45_000) {
  const deadline = Date.now() + timeoutMs;
  let last = null;

  while (Date.now() < deadline) {
    const body = await admin(
      `/admin/releases?package=${encodeURIComponent(packageName)}`,
    );
    const release = body.releases?.find((item) => item.version === version);
    if (release) {
      last = release;
      if (expected.includes(release.status)) return release;
    }
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }

  throw new Error(
    `Timed out waiting for ${packageName}@${version} to reach ${expected.join(
      " or ",
    )}. Last status: ${last?.status ?? "not found"}`,
  );
}

async function waitForAudit(packageName, version, timeoutMs = 45_000) {
  const deadline = Date.now() + timeoutMs;
  let last = null;

  while (Date.now() < deadline) {
    const body = await admin(
      `/admin/releases?package=${encodeURIComponent(packageName)}`,
    );
    const release = body.releases?.find((item) => item.version === version);
    if (release) {
      last = release;
      if (release.riskTier) return release;
    }
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }

  throw new Error(
    `Timed out waiting for the audit of ${packageName}@${version}. Last risk tier: ${
      last?.riskTier ?? "none"
    }, status: ${last?.status ?? "not found"}`,
  );
}

async function publishExample(name, version = RUN_VERSION) {
  const directory = mkdtempSync(join(tmpdir(), `trust-${name}-`));
  cpSync(join(ROOT, "examples", name), directory, { recursive: true });

  const packagePath = join(directory, "package.json");
  const manifest = JSON.parse(readFileSync(packagePath, "utf8"));
  manifest.version = version;
  writeFileSync(packagePath, `${JSON.stringify(manifest, null, 2)}\n`);
  writeFileSync(
    join(directory, ".npmrc"),
    `registry=${GATEWAY}\n//${GATEWAY.replace(/^https?:\/\//, "")}/:_authToken=${REGISTRY_TOKEN}\nalways-auth=true\n`,
  );

  log(`Publishing ${manifest.name}@${manifest.version} from ${directory}`);
  runNpm(["publish", "--access", "public", "--registry", GATEWAY], directory);

  return {
    packageName: manifest.name,
    version: manifest.version,
    directory,
  };
}

function installPackage(packageName, version, { expectSuccess }) {
  const directory = mkdtempSync(join(tmpdir(), "veripack-consumer-"));
  writeFileSync(
    join(directory, "package.json"),
    `${JSON.stringify(
      { name: "smoke-consumer", version: "1.0.0", private: true },
      null,
      2,
    )}\n`,
  );
  writeFileSync(
    join(directory, ".npmrc"),
    `registry=${GATEWAY}\n//${GATEWAY.replace(/^https?:\/\//, "")}/:_authToken=${REGISTRY_TOKEN}\nalways-auth=true\n`,
  );

  log(
    `${expectSuccess ? "Installing" : "Verifying install is blocked:"} ${packageName}@${version}`,
  );

  try {
    runNpm(
      [
        "install",
        `${packageName}@${version}`,
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        "--registry",
        GATEWAY,
      ],
      directory,
    );
    const installed = existsSync(
      join(directory, "node_modules", packageName, "package.json"),
    );

    if (expectSuccess && !installed) {
      throw new Error(`${packageName} was not installed into node_modules.`);
    }
    if (!expectSuccess) {
      throw new Error(
        `Expected ${packageName}@${version} to be blocked, but npm installed it.`,
      );
    }
  } catch (error) {
    if (expectSuccess) throw error;
    console.log(`Install was blocked as expected: ${error.message}`);
  }

  return directory;
}

async function main() {
  log(`Checking gateway health at ${GATEWAY}`);
  const healthResponse = await fetch(`${GATEWAY}/health`);
  const health = await healthResponse.json();
  if (!healthResponse.ok) {
    throw new Error(
      `Gateway is not healthy: ${healthResponse.status} ${JSON.stringify(health)}`,
    );
  }
  console.log(`Gateway healthy: ${JSON.stringify(health)}`);

  const safeBaseline = await publishExample("safe-package");
  const safePending = await waitForStatus(
    safeBaseline.packageName,
    safeBaseline.version,
    ["pending"],
  );
  const safeAudited = await waitForAudit(
    safeBaseline.packageName,
    safeBaseline.version,
  );
  if (
    safeAudited.riskTier !== "high" ||
    safeAudited.policyResult !== "warn" ||
    safeAudited.safetyVerdict !== "review"
  ) {
    throw new Error(
      `Expected the first safe release to require review, got ${safeAudited.riskTier} / ${safeAudited.policyResult} / ${safeAudited.safetyVerdict}.`,
    );
  }
  console.log(
    `First safe release requires review as expected: ${safeBaseline.packageName}@${safeBaseline.version}`,
  );

  log(`Approving ${safeBaseline.packageName}@${safeBaseline.version}`);
  await admin(`/admin/releases/${safePending.id}/approve`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      reason: "Smoke test: approved the safe package baseline.",
    }),
  });
  await waitForStatus(safeBaseline.packageName, safeBaseline.version, [
    "approved",
    "overridden",
  ]);
  installPackage(safeBaseline.packageName, safeBaseline.version, {
    expectSuccess: true,
  });

  const safe = await publishExample("safe-package", FOLLOWUP_VERSION);
  const safeApproved = await waitForStatus(safe.packageName, safe.version, [
    "approved",
  ]);
  if (
    safeApproved.riskTier !== "low" ||
    safeApproved.policyResult !== "pass" ||
    safeApproved.safetyVerdict !== "clear"
  ) {
    throw new Error(
      `Expected the safe follow-up to auto-approve as low/pass/clear, got ${safeApproved.riskTier} / ${safeApproved.policyResult} / ${safeApproved.safetyVerdict}.`,
    );
  }
  console.log(`Safe follow-up auto-approved: ${safe.packageName}@${safe.version}`);
  installPackage(safe.packageName, safe.version, { expectSuccess: true });

  const review = await publishExample("review-package");
  const pending = await waitForStatus(review.packageName, review.version, [
    "pending",
  ]);
  console.log(
    `Review release is pending as expected: ${review.packageName}@${review.version}`,
  );

  const audited = await waitForAudit(review.packageName, review.version);
  if (audited.riskTier !== "high" || audited.policyResult !== "warn") {
    throw new Error(
      `Expected the review release to be high risk / warn, got ${audited.riskTier} / ${audited.policyResult}.`,
    );
  }
  console.log(
    `Review audit complete: risk ${audited.riskTier}, policy ${audited.policyResult}`,
  );

  log(`Approving ${review.packageName}@${review.version}`);
  await admin(`/admin/releases/${pending.id}/approve`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      reason: "Smoke test: benign postinstall reviewed and approved.",
    }),
  });
  await waitForStatus(review.packageName, review.version, [
    "approved",
    "overridden",
  ]);
  installPackage(review.packageName, review.version, { expectSuccess: true });

  const risky = await publishExample("risky-package");
  await waitForStatus(risky.packageName, risky.version, ["rejected"]);
  console.log(
    `Risky release was rejected as expected: ${risky.packageName}@${risky.version}`,
  );
  installPackage(risky.packageName, risky.version, { expectSuccess: false });

  log("Smoke test passed");
  console.log(
    `Safe:   ${safeBaseline.packageName}@${safeBaseline.version} (reviewed baseline)`,
  );
  console.log(`Safe:   ${safe.packageName}@${safe.version} (auto-approved, installable)`);
  console.log(
    `Review: ${review.packageName}@${review.version} (pending → approved)`,
  );
  console.log(
    `Risky:  ${risky.packageName}@${risky.version} (rejected, not installable)`,
  );
}

main().catch((error) => {
  console.error(`\nSmoke test failed: ${error.message}`);
  process.exit(1);
});

import type {
  IntentVerdict,
  PolicyResult,
  RiskTier,
  SafetyVerdict,
  Signal,
} from "@veripack/shared";
import type { NpmVersionManifest } from "../npm/payload.js";

const LIFECYCLE_SCRIPTS = ["preinstall", "install", "postinstall", "prepare"] as const;

export interface StubAuditInput {
  packageName: string;
  version: string;
  manifest: NpmVersionManifest;
  previousManifest?: NpmVersionManifest | null;
  intent: string | null;
  tarballSize: number;
  firstRelease: boolean;
}

export interface StubAuditResult {
  safetyVerdict: SafetyVerdict;
  intentVerdict: IntentVerdict;
  riskTier: RiskTier;
  policyResult: PolicyResult;
  signals: Signal[];
  changeSet: Record<string, unknown>;
  summary: string;
  autoApprove: boolean;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isDownloadAndExecute(command: string): boolean {
  const downloader = /\b(curl|wget|fetch|Invoke-WebRequest)\b/i;
  const pipesToInterpreter = /\|\s*(sh|bash|zsh|node|python\d*|perl|ruby)\b/i;
  return downloader.test(command) && pipesToInterpreter.test(command);
}

function runtimeDependencies(manifest: NpmVersionManifest): Map<string, string> {
  const dependencies = new Map<string, string>();
  for (const field of ["dependencies", "optionalDependencies"] as const) {
    const value = manifest[field];
    if (!isRecord(value)) continue;
    for (const [name, range] of Object.entries(value)) {
      if (typeof range === "string") dependencies.set(name, range);
    }
  }
  return dependencies;
}

function dependencyDelta(
  previous: NpmVersionManifest | null | undefined,
  current: NpmVersionManifest,
): { added: Array<{ name: string; range: string }>; removed: string[]; changed: Array<{ name: string; from: string; to: string }> } {
  const previousDeps = runtimeDependencies(previous ?? {});
  const currentDeps = runtimeDependencies(current);

  const added: Array<{ name: string; range: string }> = [];
  const removed: string[] = [];
  const changed: Array<{ name: string; from: string; to: string }> = [];

  for (const [name, range] of currentDeps) {
    const oldRange = previousDeps.get(name);
    if (oldRange === undefined) {
      added.push({ name, range });
    } else if (oldRange !== range) {
      changed.push({ name, from: oldRange, to: range });
    }
  }

  for (const name of previousDeps.keys()) {
    if (!currentDeps.has(name)) removed.push(name);
  }

  return { added, removed, changed };
}

export function evaluateStubAudit(input: StubAuditInput): StubAuditResult {
  const signals: Signal[] = [];
  const scripts = isRecord(input.manifest.scripts) ? input.manifest.scripts : {};
  const presentLifecycleScripts: string[] = [];

  for (const scriptName of LIFECYCLE_SCRIPTS) {
    const command = scripts[scriptName];
    if (typeof command !== "string" || !command.trim()) continue;

    presentLifecycleScripts.push(scriptName);
    const critical = isDownloadAndExecute(command);
    signals.push({
      type: "install_script",
      severity: critical ? "critical" : "high",
      source: "deterministic",
      ruleId: critical ? "install-script-download-exec" : "install-script",
      message: critical
        ? `${scriptName} downloads and executes remote code.`
        : `${scriptName} is present and needs review.`,
      evidence: { script: scriptName, command },
    });
  }

  if (presentLifecycleScripts.length === 0) {
    signals.push({
      type: "no_install_scripts",
      severity: "info",
      source: "deterministic",
      ruleId: "no-install-scripts",
      message: "No install lifecycle scripts are present.",
    });
  }

  if (!input.intent) {
    signals.push({
      type: "missing_release_intent",
      severity: "medium",
      source: "deterministic",
      ruleId: "release-intent-required",
      message:
        "No release intent was supplied. Add a trust.intent note to package.json.",
    });
  }

  if (input.tarballSize > 5 * 1024 * 1024) {
    signals.push({
      type: "large_tarball",
      severity: "info",
      source: "deterministic",
      ruleId: "tarball-size",
      message: `Tarball is ${(input.tarballSize / 1024 / 1024).toFixed(1)} MiB.`,
      evidence: { bytes: input.tarballSize },
    });
  }

  if (input.firstRelease) {
    signals.push({
      type: "first_release",
      severity: "info",
      source: "deterministic",
      ruleId: "first-release",
      message: "This is the first release of the package in this registry.",
    });
  }

  const dependencyChangeSet = dependencyDelta(
    input.previousManifest,
    input.manifest,
  );

  if (dependencyChangeSet.added.length > 0) {
    signals.push({
      type: "new_dependencies",
      severity: "info",
      source: "deterministic",
      ruleId: "dependency-delta",
      message: `${dependencyChangeSet.added.length} new runtime ${
        dependencyChangeSet.added.length === 1 ? "dependency" : "dependencies"
      }.`,
      evidence: { added: dependencyChangeSet.added },
    });
  }

  const hasCritical = signals.some((signal) => signal.severity === "critical");
  const hasHigh = signals.some((signal) => signal.severity === "high");
  const hasMedium = signals.some((signal) => signal.severity === "medium");

  let riskTier: RiskTier;
  let safetyVerdict: SafetyVerdict;
  let policyResult: PolicyResult;

  if (hasCritical) {
    riskTier = "critical";
    safetyVerdict = "block";
    policyResult = "block";
  } else if (hasHigh) {
    riskTier = "high";
    safetyVerdict = "review";
    policyResult = "warn";
  } else if (hasMedium) {
    riskTier = "medium";
    safetyVerdict = "review";
    policyResult = "warn";
  } else {
    riskTier = "low";
    safetyVerdict = "clear";
    policyResult = "pass";
  }

  const intentVerdict: IntentVerdict = input.intent
    ? hasCritical
      ? "mismatch"
      : "matches"
    : "unknown";

  const summary = hasCritical
    ? "Critical install-script pattern detected. The release is blocked."
    : hasHigh
      ? "The release adds or changes an install script and needs review."
      : hasMedium
        ? "The release has no install scripts, but release intent is missing."
        : "No install scripts and no medium-or-higher signals. Eligible for auto-approval.";

  return {
    safetyVerdict,
    intentVerdict,
    riskTier,
    policyResult,
    signals,
    changeSet: {
      scripts: Object.fromEntries(
        presentLifecycleScripts.map((name) => [name, scripts[name]]),
      ),
      dependencies: dependencyChangeSet,
      tarballSize: input.tarballSize,
      engine: "stub",
    },
    summary,
    autoApprove: riskTier === "low" && policyResult === "pass",
  };
}

import {
  type AuditPolicy,
  type PolicyHighRiskAuthority,
  type PolicyReviewAuthority,
  type PolicyResult,
  type PolicyVerdict,
  type RiskTier,
  type SafetyVerdict,
  type Signal,
} from "@veripack/shared";
import { z } from "zod";

export type { AuditPolicy } from "@veripack/shared";

export const DEFAULT_POLICY_VERSION = "v1-default-1";

export const DEFAULT_AUDIT_POLICY: AuditPolicy = {
  version: DEFAULT_POLICY_VERSION,
  firstRelease: { review: true },
  autoApproval: {
    enabled: true,
    maxDiffFiles: 50,
    maxDiffLines: 2_000,
    allowDocsOnly: true,
    allowVersionOnly: true,
  },
  review: { medium: "reviewer", high: "reviewer" },
  provenance: { required: false },
  installScripts: { allow: [], deny: [] },
  packages: { banned: [], requiredVerdicts: {} },
  scopes: { requiredVerdicts: {}, twoReviewer: [] },
  yank: { requireReview: true },
  quarantine: { requireReview: true },
  selfApproval: { enabled: false, maxRiskTier: "medium" },
};

/**
 * Hard safety rules. These are constants, never policy fields, so no policy
 * payload can disable them.
 */
export const SAFETY_FLOOR = {
  blockDeterministicCritical: true,
  requirePreviousArtifactForAutoApproval: true,
  forbidAutoApprovalForBinary: true,
  forbidAutoApprovalForObfuscation: true,
  requireReleaseIntent: true,
} as const;

const LEGACY_POLICY_FIELDS = [
  "requireFirstReleaseReview",
  "requireReleaseIntent",
  "requireCompleteDiffForAutoApproval",
  "blockCriticalFindings",
  "autoApproveLowRisk",
] as const;

const V2_POLICY_FIELDS = [
  "firstRelease",
  "autoApproval",
  "review",
  "provenance",
  "installScripts",
  "packages",
  "scopes",
  "yank",
  "quarantine",
  "selfApproval",
] as const;

const verdictSchema = z.enum(["clear", "review", "block"]);
const authoritySchema = z.enum(["reviewer", "admin"]);

const policySchema = z
  .object({
    version: z.string().trim().min(1).max(120),
    firstRelease: z.object({ review: z.boolean() }).strict(),
    autoApproval: z
      .object({
        enabled: z.boolean(),
        maxDiffFiles: z.number().int().positive().max(100_000),
        maxDiffLines: z.number().int().positive().max(1_000_000),
        allowDocsOnly: z.boolean(),
        allowVersionOnly: z.boolean(),
      })
      .strict(),
    review: z
      .object({
        medium: authoritySchema,
        high: z.enum(["reviewer", "admin", "two_reviewers"]),
      })
      .strict(),
    provenance: z.object({ required: z.boolean() }).strict(),
    installScripts: z
      .object({
        allow: z.array(z.string().min(1).max(200)).max(200),
        deny: z.array(z.string().min(1).max(200)).max(200),
      })
      .strict(),
    packages: z
      .object({
        banned: z.array(z.string().min(1).max(214)).max(500),
        requiredVerdicts: z.record(
          z.string().min(1).max(214),
          verdictSchema,
        ),
      })
      .strict(),
    scopes: z
      .object({
        requiredVerdicts: z.record(
          z.string().min(1).max(214),
          verdictSchema,
        ),
        twoReviewer: z.array(z.string().min(1).max(214)).max(500),
      })
      .strict(),
    yank: z.object({ requireReview: z.boolean() }).strict(),
    quarantine: z.object({ requireReview: z.boolean() }).strict(),
    selfApproval: z
      .object({
        enabled: z.boolean(),
        maxRiskTier: z.literal("medium"),
      })
      .strict(),
  })
  .strict();

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function deepMerge(
  base: Record<string, unknown>,
  override: Record<string, unknown>,
): Record<string, unknown> {
  const result: Record<string, unknown> = { ...base };
  for (const [key, value] of Object.entries(override)) {
    const previous = result[key];
    result[key] =
      isPlainObject(previous) && isPlainObject(value)
        ? deepMerge(previous, value)
        : value;
  }
  return result;
}

export function isLegacyAuditPolicy(value: unknown): boolean {
  if (!isPlainObject(value)) return false;
  const hasLegacy = LEGACY_POLICY_FIELDS.some((field) => field in value);
  if (!hasLegacy) return false;
  return !V2_POLICY_FIELDS.some((field) => field in value);
}

/**
 * Maps the pre-V1 five-boolean policy onto the structured model. The mapping
 * is also recorded in ADR 0011. Deliberately dropped:
 * - `blockCriticalFindings` and `requireCompleteDiffForAutoApproval` become
 *   non-configurable safety-floor rules;
 * - `requireReleaseIntent` becomes a floor rule.
 */
export function migrateLegacyAuditPolicy(
  legacy: Record<string, unknown>,
): Record<string, unknown> {
  for (const field of LEGACY_POLICY_FIELDS) {
    if (field in legacy && typeof legacy[field] !== "boolean") {
      throw new Error(`Legacy policy field "${field}" must be boolean.`);
    }
  }

  return {
    version:
      typeof legacy.version === "string"
        ? legacy.version
        : DEFAULT_POLICY_VERSION,
    firstRelease: {
      review: legacy.requireFirstReleaseReview !== false,
    },
    autoApproval: {
      enabled: legacy.autoApproveLowRisk !== false,
      maxDiffFiles: DEFAULT_AUDIT_POLICY.autoApproval.maxDiffFiles,
      maxDiffLines: DEFAULT_AUDIT_POLICY.autoApproval.maxDiffLines,
      allowDocsOnly: DEFAULT_AUDIT_POLICY.autoApproval.allowDocsOnly,
      allowVersionOnly: DEFAULT_AUDIT_POLICY.autoApproval.allowVersionOnly,
    },
    review: { ...DEFAULT_AUDIT_POLICY.review },
    provenance: { ...DEFAULT_AUDIT_POLICY.provenance },
    installScripts: {
      allow: [...DEFAULT_AUDIT_POLICY.installScripts.allow],
      deny: [...DEFAULT_AUDIT_POLICY.installScripts.deny],
    },
    packages: {
      banned: [],
      requiredVerdicts: {},
    },
    scopes: {
      requiredVerdicts: {},
      twoReviewer: [],
    },
    yank: { ...DEFAULT_AUDIT_POLICY.yank },
    quarantine: { ...DEFAULT_AUDIT_POLICY.quarantine },
    selfApproval: { ...DEFAULT_AUDIT_POLICY.selfApproval },
  };
}

function canonicalValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return [...value].sort((a, b) =>
      JSON.stringify(a).localeCompare(JSON.stringify(b)),
    );
  }
  if (isPlainObject(value)) {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalValue(value[key])]),
    );
  }
  return value;
}

export function canonicalizePolicy(
  policy: AuditPolicy,
  options: { includeVersion?: boolean } = {},
): Record<string, unknown> {
  const { version, ...rest } = policy;
  const candidate = options.includeVersion === true ? { version, ...rest } : rest;
  return canonicalValue(candidate) as Record<string, unknown>;
}

export function canonicalPolicyJson(
  policy: AuditPolicy,
  options: { includeVersion?: boolean } = {},
): string {
  return JSON.stringify(canonicalizePolicy(policy, options));
}

export type PolicyChangeDirection = "tighten" | "loosen";

export interface PolicyDiffEntry {
  path: string;
  before: unknown;
  after: unknown;
  direction: PolicyChangeDirection;
}

function flattenPolicy(
  value: unknown,
  prefix: string,
  target: Map<string, unknown>,
): void {
  if (isPlainObject(value)) {
    for (const [key, child] of Object.entries(value)) {
      flattenPolicy(child, prefix ? `${prefix}.${key}` : key, target);
    }
    return;
  }
  target.set(prefix, value);
}

function stringSet(value: unknown): Set<string> {
  return new Set(
    Array.isArray(value)
      ? value.filter((item): item is string => typeof item === "string")
      : [],
  );
}

function arrayChange(valueBefore: unknown, valueAfter: unknown): {
  added: number;
  removed: number;
} {
  const before = stringSet(valueBefore);
  const after = stringSet(valueAfter);
  let added = 0;
  let removed = 0;
  for (const item of after) if (!before.has(item)) added += 1;
  for (const item of before) if (!after.has(item)) removed += 1;
  return { added, removed };
}

const AUTHORITY_RANK: Record<string, number> = {
  reviewer: 0,
  admin: 1,
  two_reviewers: 2,
};

const VERDICT_RANK: Record<string, number> = {
  clear: 0,
  review: 1,
  block: 2,
};

function classifyDirection(
  path: string,
  before: unknown,
  after: unknown,
): PolicyChangeDirection {
  switch (path) {
    case "firstRelease.review":
    case "provenance.required":
    case "yank.requireReview":
    case "quarantine.requireReview":
      return after === true ? "tighten" : "loosen";
    case "autoApproval.enabled":
    case "autoApproval.allowDocsOnly":
    case "autoApproval.allowVersionOnly":
    case "selfApproval.enabled":
      return after === true ? "loosen" : "tighten";
    case "autoApproval.maxDiffFiles":
    case "autoApproval.maxDiffLines":
      return Number(after) > Number(before) ? "loosen" : "tighten";
    case "review.medium":
    case "review.high":
      return (AUTHORITY_RANK[String(after)] ?? 0) >
        (AUTHORITY_RANK[String(before)] ?? 0)
        ? "tighten"
        : "loosen";
    case "installScripts.allow": {
      const { added } = arrayChange(before, after);
      return added > 0 ? "loosen" : "tighten";
    }
    case "installScripts.deny":
    case "packages.banned":
    case "scopes.twoReviewer": {
      const { removed } = arrayChange(before, after);
      return removed > 0 ? "loosen" : "tighten";
    }
    default:
      if (
        path.startsWith("packages.requiredVerdicts.") ||
        path.startsWith("scopes.requiredVerdicts.")
      ) {
        return (VERDICT_RANK[String(after)] ?? 0) >
          (VERDICT_RANK[String(before)] ?? 0)
          ? "tighten"
          : "loosen";
      }
      // Unknown paths cannot exist under the strict schema. Treat a change as
      // tightening so an unexpected field cannot bypass approval.
      return "tighten";
  }
}

export function diffPolicies(
  before: AuditPolicy,
  after: AuditPolicy,
): PolicyDiffEntry[] {
  const beforeFlat = new Map<string, unknown>();
  const afterFlat = new Map<string, unknown>();
  flattenPolicy(canonicalizePolicy(before), "", beforeFlat);
  flattenPolicy(canonicalizePolicy(after), "", afterFlat);

  const paths = new Set([...beforeFlat.keys(), ...afterFlat.keys()]);
  const changes: PolicyDiffEntry[] = [];
  for (const path of [...paths].sort()) {
    if (path === "version") continue;
    const previous = beforeFlat.get(path);
    const next = afterFlat.get(path);
    if (JSON.stringify(previous) === JSON.stringify(next)) continue;
    changes.push({
      path,
      before: previous ?? null,
      after: next ?? null,
      direction: classifyDirection(path, previous, next),
    });
  }
  return changes;
}

export function policyDirection(
  changes: PolicyDiffEntry[],
): PolicyChangeDirection | "none" {
  if (changes.some((change) => change.direction === "loosen")) return "loosen";
  return changes.length > 0 ? "tighten" : "none";
}

function sameSemantics(a: AuditPolicy, b: AuditPolicy): boolean {
  return (
    canonicalPolicyJson(a) === canonicalPolicyJson(b)
  );
}

export function parseAuditPolicy(
  version: string = DEFAULT_POLICY_VERSION,
  json = "{}",
): AuditPolicy {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (error) {
    throw new Error(
      `AUDIT_POLICY_JSON must be valid JSON: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }

  if (!isPlainObject(parsed)) {
    throw new Error("AUDIT_POLICY_JSON must be a JSON object.");
  }

  const candidate = isLegacyAuditPolicy(parsed)
    ? migrateLegacyAuditPolicy(parsed)
    : parsed;

  const candidateVersion = version.trim() || DEFAULT_POLICY_VERSION;
  const declaredVersion = candidate.version;
  if (
    typeof declaredVersion === "string" &&
    declaredVersion.trim() &&
    declaredVersion.trim() !== candidateVersion
  ) {
    throw new Error(
      `Policy version "${declaredVersion}" does not match the requested version "${candidateVersion}".`,
    );
  }

  const merged = deepMerge(DEFAULT_AUDIT_POLICY as unknown as Record<string, unknown>, {
    ...candidate,
    version: candidateVersion,
  });

  let policy: AuditPolicy;
  try {
    policy = policySchema.parse(merged) as AuditPolicy;
  } catch (error) {
    if (error instanceof z.ZodError) {
      const issue = error.issues[0];
      const path = issue?.path.join(".") || "(root)";
      throw new Error(
        `Invalid audit policy at ${path}: ${issue?.message ?? "invalid value"}.`,
      );
    }
    throw error;
  }

  if (
    sameSemantics(policy, DEFAULT_AUDIT_POLICY) === false &&
    policy.version === DEFAULT_POLICY_VERSION
  ) {
    throw new Error(
      `Audit policy changed semantically but kept version "${DEFAULT_POLICY_VERSION}"; bump the policy version.`,
    );
  }

  return policy;
}

export interface PolicyInput {
  signals: Signal[];
  intent: string | null;
  firstRelease: boolean;
  previousUnavailable: boolean;
  packageName?: string;
  scopeKey?: string;
  diffFiles?: number;
  diffLines?: number;
}

export interface PolicyEvaluation {
  safetyVerdict: SafetyVerdict;
  riskTier: RiskTier;
  policyResult: PolicyResult;
  summary: string;
  autoApprove: boolean;
  requiredApprovals: number;
  reviewAuthority: PolicyReviewAuthority;
}

const FIRST_RELEASE_SIGNAL = "first_release";
const BINARY_SIGNAL = "binary_or_wasm_artifact";
const OBFUSCATION_SIGNAL = "minified_code_added";
const INSTALL_SCRIPT_SIGNALS = new Set([
  "install_script",
  "install_script_added",
  "install_script_changed",
  "install_script_download_exec",
  "bundled_dependency_install_script",
]);

function matchesPattern(pattern: string, value: string): boolean {
  if (pattern === "*") return true;
  if (pattern.endsWith("/*")) return value.startsWith(pattern.slice(0, -1));
  return pattern === value;
}

function packageScope(packageName: string): string | null {
  if (!packageName.startsWith("@")) return null;
  const slash = packageName.indexOf("/");
  return slash > 1 ? packageName.slice(0, slash) : null;
}

function matchesPackageOrScope(
  patterns: string[],
  packageName: string,
  scopeKey: string | undefined,
): boolean {
  const scope = packageScope(packageName);
  return patterns.some(
    (pattern) =>
      matchesPattern(pattern, packageName) ||
      (scope !== null && matchesPattern(pattern, scope)) ||
      (scopeKey !== undefined && matchesPattern(pattern, scopeKey)),
  );
}

function requiredVerdict(
  policy: AuditPolicy,
  packageName: string,
  scopeKey: string | undefined,
): PolicyVerdict {
  let required: PolicyVerdict = "clear";
  const consider = (pattern: string, verdict: PolicyVerdict) => {
    const scope = packageScope(packageName);
    const matches =
      matchesPattern(pattern, packageName) ||
      (scope !== null && matchesPattern(pattern, scope)) ||
      (scopeKey !== undefined && matchesPattern(pattern, scopeKey));
    if (matches && VERDICT_RANK[verdict] > VERDICT_RANK[required]) {
      required = verdict;
    }
  };

  for (const [pattern, verdict] of Object.entries(
    policy.packages.requiredVerdicts,
  )) {
    consider(pattern, verdict);
  }
  for (const [pattern, verdict] of Object.entries(
    policy.scopes.requiredVerdicts,
  )) {
    consider(pattern, verdict);
  }
  return required;
}

function deniedInstallScript(
  policy: AuditPolicy,
  signals: Signal[],
  packageName: string | undefined,
): boolean {
  if (policy.installScripts.deny.length === 0) return false;
  const denied = new Set(policy.installScripts.deny);
  if (packageName && matchesPackageOrScope([...denied], packageName, undefined)) {
    if (
      signals.some(
        (signal) =>
          INSTALL_SCRIPT_SIGNALS.has(signal.type) ||
          signal.type.startsWith("install_script"),
      )
    ) {
      return true;
    }
  }
  return signals.some((signal) => {
    const script = signal.evidence?.script;
    return (
      (INSTALL_SCRIPT_SIGNALS.has(signal.type) ||
        signal.type.startsWith("install_script")) &&
      typeof script === "string" &&
      denied.has(script)
    );
  });
}

function enabledSignals(input: PolicyInput, policy: AuditPolicy): Signal[] {
  return input.signals.filter(
    (signal) =>
      signal.type !== FIRST_RELEASE_SIGNAL || policy.firstRelease.review,
  );
}

export function evaluatePolicy(
  input: PolicyInput,
  policy: AuditPolicy = DEFAULT_AUDIT_POLICY,
): PolicyEvaluation {
  const signals = enabledSignals(input, policy);
  const packageName = input.packageName ?? "";
  const verdictRequired = requiredVerdict(policy, packageName, input.scopeKey);
  const bannedPackage =
    packageName !== "" && matchesPackageOrScope(policy.packages.banned, packageName, undefined);
  const blockedScript = deniedInstallScript(policy, signals, packageName);

  const hasCritical = signals.some((signal) => signal.severity === "critical");
  const hasHigh =
    signals.some((signal) => signal.severity === "high") ||
    (policy.firstRelease.review && input.firstRelease);
  const hasMedium =
    signals.some((signal) => signal.severity === "medium") ||
    !input.intent ||
    input.previousUnavailable ||
    verdictRequired === "review";

  let riskTier: RiskTier;
  let safetyVerdict: SafetyVerdict;
  let policyResult: PolicyResult;

  if (
    SAFETY_FLOOR.blockDeterministicCritical &&
    (hasCritical || bannedPackage || blockedScript || verdictRequired === "block")
  ) {
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

  const docsOnly = signals.some(
    (signal) => signal.type === "docs_tests_only",
  );
  const versionOnly = signals.some(
    (signal) => signal.type === "version_bump_no_code_change",
  );
  const hasBinary = signals.some((signal) => signal.type === BINARY_SIGNAL);
  const hasObfuscation = signals.some(
    (signal) => signal.type === OBFUSCATION_SIGNAL,
  );
  const hasNewDependencies = signals.some(
    (signal) => signal.type === "new_dependencies",
  );
  const hasInstallScript = signals.some(
    (signal) =>
      INSTALL_SCRIPT_SIGNALS.has(signal.type) ||
      signal.type.startsWith("install_script"),
  );
  const hasNewCapability = signals.some((signal) =>
    signal.type.startsWith("new_capability_"),
  );
  const twoReviewerScope = matchesPackageOrScope(
    policy.scopes.twoReviewer,
    packageName,
    input.scopeKey,
  );
  // A two-reviewer scope binds every risk tier in it; the review.high
  // authority setting binds high-risk releases specifically.
  const requiredApprovals =
    twoReviewerScope ||
    (riskTier === "high" && policy.review.high === "two_reviewers")
      ? 2
      : 1;

  const changeEligible =
    (docsOnly && policy.autoApproval.allowDocsOnly) ||
    (versionOnly && policy.autoApproval.allowVersionOnly);
  const diffWithinLimits =
    (input.diffFiles ?? 0) <= policy.autoApproval.maxDiffFiles &&
    (input.diffLines ?? 0) <= policy.autoApproval.maxDiffLines;

  const autoApprove =
    policy.autoApproval.enabled &&
    requiredApprovals === 1 &&
    changeEligible &&
    riskTier === "low" &&
    policyResult === "pass" &&
    Boolean(input.intent) &&
    !input.previousUnavailable &&
    !hasBinary &&
    !hasObfuscation &&
    !hasNewDependencies &&
    !hasInstallScript &&
    !hasNewCapability &&
    diffWithinLimits &&
    !(policy.firstRelease.review && input.firstRelease);

  const summary =
    policyResult === "block"
      ? bannedPackage
        ? "The package is banned by policy. The release is blocked."
        : blockedScript
          ? "The package uses an install script denied by policy. The release is blocked."
          : "Critical deterministic finding detected. The release is blocked."
      : riskTier === "high"
        ? "The release has high-risk findings and needs review."
        : riskTier === "medium"
          ? "The release has medium-risk findings and needs review."
          : autoApprove
            ? "Only documentation or version metadata changed. Eligible for auto-approval."
            : "No medium-or-higher deterministic findings. Manual approval is required by policy.";

  const authorityForRisk: PolicyReviewAuthority =
    riskTier === "critical"
      ? "admin"
      : riskTier === "high"
        ? policy.review.high === "two_reviewers"
          ? "reviewer"
          : policy.review.high
        : policy.review.medium;

  return {
    safetyVerdict,
    riskTier,
    policyResult,
    summary,
    autoApprove,
    requiredApprovals,
    reviewAuthority: authorityForRisk,
  };
}

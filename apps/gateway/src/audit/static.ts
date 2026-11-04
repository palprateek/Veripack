import type {
  IntentVerdict,
  PolicyResult,
  RiskTier,
  SafetyVerdict,
  Signal,
} from "@veripack/shared";
import type { NpmVersionManifest } from "../npm/payload.js";
import {
  ArchiveError,
  analyzeSourceFiles,
  readArchive,
  type ArchiveInventory,
  type ArchiveLimits,
} from "./archive.js";
import {
  analyzeCode,
  type CodeAnalysis,
} from "./capabilities.js";
import {
  buildChangeSetPayload,
  buildStaticChangeSet,
  dependencyProvenance,
  isRecord,
  type DependencyProvenance,
} from "./change-set.js";
import {
  DEFAULT_AUDIT_POLICY,
  evaluatePolicy,
  type AuditPolicy,
} from "./policy.js";
import { evaluateStaticRules } from "./rules.js";

export type { DependencyProvenance } from "./change-set.js";

export interface PreviousReleaseInput {
  version: string;
  publisher: string;
  manifest: NpmVersionManifest;
  tarball: Buffer | null;
}

export interface StaticAuditInput {
  packageName: string;
  version: string;
  publisher: string;
  manifest: NpmVersionManifest;
  intent: string | null;
  tarball: Buffer;
  previous: PreviousReleaseInput | null;
  firstRelease: boolean;
  scopeKey?: string;
  limits?: Partial<ArchiveLimits>;
  policy?: AuditPolicy;
}

export interface StaticAuditResult {
  policyVersion: string;
  safetyVerdict: SafetyVerdict;
  intentVerdict: IntentVerdict;
  riskTier: RiskTier;
  policyResult: PolicyResult;
  signals: Signal[];
  changeSet: Record<string, unknown>;
  summary: string;
  autoApprove: boolean;
  policyMetrics?: { diffFiles: number; diffLines: number };
}

export interface ArtifactAnalysis {
  inventory: ArchiveInventory;
  code: CodeAnalysis;
  dependencyProvenance: DependencyProvenance;
}

export interface StaticAuditArtifacts {
  current: ArtifactAnalysis;
  previous: ArtifactAnalysis | null;
  previousUnavailable: boolean;
}

/** Cache evidence without retaining analyzed source text in Postgres. */
export function serializeArtifactAnalysis(
  analysis: ArtifactAnalysis,
): ArtifactAnalysis {
  return {
    inventory: {
      ...analysis.inventory,
      files: analysis.inventory.files.map((file) => ({
        ...file,
        content: null,
      })),
    },
    code: analysis.code,
    dependencyProvenance: analysis.dependencyProvenance,
  };
}

export function deserializeArtifactAnalysis(
  value: unknown,
): ArtifactAnalysis | null {
  if (!isRecord(value)) return null;
  const inventory = value.inventory;
  const code = value.code;
  const provenance = value.dependencyProvenance;
  if (!isRecord(inventory) || !isRecord(code) || !isRecord(provenance)) return null;
  if (!Array.isArray(inventory.files) || !Array.isArray(code.findings)) {
    return null;
  }
  if (
    !Array.isArray(provenance.bundledPackages) ||
    !Array.isArray(provenance.installScripts) ||
    !Array.isArray(provenance.lockfiles) ||
    !Array.isArray(provenance.lockfileInstallScripts)
  ) {
    return null;
  }

  return {
    inventory: {
      ...(inventory as unknown as ArchiveInventory),
      files: inventory.files.map((file) => ({
        ...(file as Record<string, unknown>),
        content: null,
      })) as ArtifactAnalysis["inventory"]["files"],
    },
    code: {
      ...(code as unknown as CodeAnalysis),
      languages: isRecord(code.languages)
        ? (code.languages as Record<string, number>)
        : {},
    },
    dependencyProvenance: provenance as unknown as DependencyProvenance,
  };
}

function fatalResult(
  code: string,
  message: string,
  detail: Record<string, unknown>,
  policyVersion = DEFAULT_AUDIT_POLICY.version,
): StaticAuditResult {
  return {
    policyVersion,
    safetyVerdict: "block",
    intentVerdict: "unknown",
    riskTier: "critical",
    policyResult: "block",
    signals: [
      {
        type: code,
        ruleId: code,
        severity: "critical",
        source: "deterministic",
        message,
        evidence: detail,
      },
    ],
    changeSet: {
      engine: "static",
      policy: { version: policyVersion },
      archive: { error: code, detail },
    },
    summary: message,
    autoApprove: false,
  };
}

export async function analyzeStaticArtifact(
  tarball: Buffer,
  limits?: Partial<ArchiveLimits>,
): Promise<ArtifactAnalysis> {
  const inventory = await readArchive(tarball, limits);
  return {
    inventory,
    code: analyzeCode(analyzeSourceFiles(inventory)),
    dependencyProvenance: dependencyProvenance(inventory),
  };
}

export async function evaluateStaticAudit(
  input: StaticAuditInput,
  artifacts?: Partial<StaticAuditArtifacts>,
): Promise<StaticAuditResult> {
  const policy = input.policy ?? DEFAULT_AUDIT_POLICY;

  let current: ArtifactAnalysis;
  try {
    current = artifacts?.current ?? (await analyzeStaticArtifact(input.tarball, input.limits));
  } catch (error) {
    if (error instanceof ArchiveError) {
      return fatalResult(
        `archive_${error.code}`,
        error.message,
        error.detail,
        policy.version,
      );
    }
    throw error;
  }

  let previous: ArtifactAnalysis | null = null;
  let previousUnavailable = false;
  const previousUnavailableSignal: Signal[] = [];
  if (input.previous) {
    if (artifacts && "previous" in artifacts) {
      previous = artifacts.previous ?? null;
      previousUnavailable = artifacts.previousUnavailable ?? false;
      if (!previous && !previousUnavailable) previousUnavailable = true;
      if (previousUnavailable) {
        previousUnavailableSignal.push({
          type: "previous_artifact_unavailable",
          ruleId: "previous-artifact-unavailable",
          severity: "medium",
          source: "deterministic",
          message:
            "The previous release tarball could not be analyzed, so the diff is incomplete.",
          evidence: { version: input.previous.version },
        });
      }
    } else if (input.previous.tarball) {
      try {
        previous = await analyzeStaticArtifact(input.previous.tarball, input.limits);
      } catch (error) {
        previousUnavailable = true;
        previousUnavailableSignal.push({
          type: "previous_artifact_unavailable",
          ruleId: "previous-artifact-unavailable",
          severity: "medium",
          source: "deterministic",
          message:
            "The previous release tarball could not be analyzed, so the diff is incomplete.",
          evidence: {
            version: input.previous.version,
            error: error instanceof Error ? error.message : String(error),
          },
        });
      }
    } else {
      previousUnavailable = true;
      previousUnavailableSignal.push({
        type: "previous_artifact_unavailable",
        ruleId: "previous-artifact-unavailable",
        severity: "medium",
        source: "deterministic",
        message:
          "The previous release has no stored tarball, so the diff is incomplete.",
        evidence: { version: input.previous.version },
      });
    }
  }

  const change = buildStaticChangeSet(input, current, previous);
  const signals = [
    ...previousUnavailableSignal,
    ...evaluateStaticRules({
      input,
      current,
      previous,
      previousUnavailable,
      change,
    }),
  ];

  const policyEvaluation = evaluatePolicy(
    {
      signals,
      intent: input.intent,
      firstRelease: input.firstRelease,
      previousUnavailable,
      packageName: input.packageName,
      scopeKey: input.scopeKey,
      diffFiles: change.paths.length,
      diffLines: change.changedLines,
    },
    policy,
  );

  const intentVerdict: IntentVerdict = input.intent
    ? signals.some((signal) => signal.severity === "critical")
      ? "mismatch"
      : "matches"
    : "unknown";

  return {
    policyVersion: policy.version,
    safetyVerdict: policyEvaluation.safetyVerdict,
    intentVerdict,
    riskTier: policyEvaluation.riskTier,
    policyResult: policyEvaluation.policyResult,
    signals,
    changeSet: buildChangeSetPayload(input, current, change, policy.version),
    summary: policyEvaluation.summary,
    autoApprove: policyEvaluation.autoApprove,
    policyMetrics: {
      diffFiles: change.paths.length,
      diffLines: change.changedLines,
    },
  };
}

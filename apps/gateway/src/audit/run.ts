import type { Signal } from "@veripack/shared";
import type { Db } from "../db.js";
import type { NpmVersionManifest } from "../npm/payload.js";
import type { SandboxResult } from "../sandbox.js";
import { llmUnavailableSignal, mergeLlmReview } from "./aggregate.js";
import { ArchiveError } from "./archive.js";
import {
  getCachedArtifact,
  putCachedArtifact,
  type AuditCacheKey,
} from "./cache.js";
import type { LlmAuditBackend, LlmAuditReview } from "./llm.js";
import { detectNameSignals } from "./name-signals.js";
import type { AuditPolicy } from "./policy.js";
import {
  analyzeStaticArtifact,
  evaluateStaticAudit,
  type ArtifactAnalysis,
  type StaticAuditArtifacts,
  type StaticAuditResult,
} from "./static.js";

export interface AuditRunLogger {
  info(obj: unknown, message?: string): void;
  error(obj: unknown, message?: string): void;
}

export interface AuditArtifactCache {
  get(key: AuditCacheKey): Promise<ArtifactAnalysis | null>;
  put(key: AuditCacheKey, artifact: ArtifactAnalysis): Promise<void>;
}

export interface AuditRunPrevious {
  version: string;
  publisher: string;
  manifest: NpmVersionManifest;
  tarball: Buffer | null;
  tarballDigest: string | null;
}

export interface AuditRunInput {
  releaseId?: string;
  packageName: string;
  version: string;
  publisher: string;
  manifest: NpmVersionManifest;
  intent: string | null;
  tarball: Buffer;
  tarballDigest: string;
  previous: AuditRunPrevious | null;
  firstRelease: boolean;
  policy: AuditPolicy;
  scopeKey: string;
  engineVersion: string;
  cache: AuditArtifactCache | null;
  sandbox: ((tarball: Buffer) => Promise<SandboxResult>) | null;
  llm: LlmAuditBackend | null;
  /** Analysis already computed by a caller that needed the archive manifest. */
  prepared?: Pick<StaticAuditArtifacts, "current">;
  /** Existing package names for typosquat/collision signals (V2). */
  existingPackageNames?: string[];
}

export interface AuditRunResult {
  result: StaticAuditResult;
  llmReview: LlmAuditReview | null;
  sandbox: SandboxResult | null;
  startedAt: Date;
}

export function createArtifactCache(db: Db): AuditArtifactCache {
  return {
    get: (key) => getCachedArtifact(db, key),
    put: (key, artifact) => putCachedArtifact(db, key, artifact),
  };
}

const NOOP_LOGGER: AuditRunLogger = {
  info: () => undefined,
  error: () => undefined,
};

async function analyzeWithCache(
  input: AuditRunInput,
  tarball: Buffer,
  digest: string | null,
  logger: AuditRunLogger,
): Promise<ArtifactAnalysis> {
  if (!digest || !input.cache) return analyzeStaticArtifact(tarball);

  const key = {
    scopeKey: input.scopeKey,
    tarballDigest: digest,
    engineVersion: input.engineVersion,
  };
  const cached = await input.cache.get(key);
  if (cached) {
    logger.info(
      {
        releaseId: input.releaseId,
        ...key,
      },
      "reusing cached static artifact analysis",
    );
    return cached;
  }

  const analyzed = await analyzeStaticArtifact(tarball);
  try {
    await input.cache.put(key, analyzed);
  } catch (error) {
    // Cache storage is an optimization. A cache write failure must not turn a
    // completed static audit into a failed release.
    logger.error(
      {
        releaseId: input.releaseId,
        ...key,
        error: error instanceof Error ? error.message : String(error),
      },
      "failed to persist static artifact analysis cache",
    );
  }
  return analyzed;
}

function appendSignal(
  result: StaticAuditResult,
  signal: Signal,
  changeSet: Record<string, unknown>,
): StaticAuditResult {
  return {
    ...result,
    signals: [...result.signals, signal],
    changeSet: { ...result.changeSet, ...changeSet },
  };
}

function withSandbox(
  result: StaticAuditResult,
  sandbox: SandboxResult,
): StaticAuditResult {
  const failed = sandbox.timedOut || sandbox.exitCode !== 0;
  return appendSignal(
    result,
    {
      type: "sandbox_execution",
      ruleId: "sandbox-execution",
      severity: failed ? "medium" : "info",
      source: "deterministic",
      message: failed
        ? "The isolated package entrypoint did not complete successfully."
        : "The package entrypoint completed inside the network-isolated sandbox.",
      evidence: {
        exitCode: sandbox.exitCode,
        signal: sandbox.signal,
        timedOut: sandbox.timedOut,
        durationMs: sandbox.durationMs,
        stdout: sandbox.stdout,
        stderr: sandbox.stderr,
      },
    },
    { sandbox },
  );
}

function withSandboxFailure(
  result: StaticAuditResult,
  error: unknown,
): StaticAuditResult {
  const message = error instanceof Error ? error.message : String(error);
  return appendSignal(
    result,
    {
      type: "sandbox_unavailable",
      ruleId: "sandbox-unavailable",
      severity: "medium",
      source: "deterministic",
      message: "The configured dynamic sandbox could not be started.",
      evidence: { error: message.slice(0, 500) },
    },
    { sandbox: { enabled: true, error: message.slice(0, 500) } },
  );
}

/**
 * Run the full audit pipeline: artifact analysis (cached by scope + digest +
 * engine), deterministic evaluation, optional sandbox, then optional LLM
 * review merged over the deterministic result.
 */
export async function runAudit(
  input: AuditRunInput,
  logger: AuditRunLogger = NOOP_LOGGER,
): Promise<AuditRunResult> {
  let current: ArtifactAnalysis | null = input.prepared?.current ?? null;
  if (!current) {
    try {
      current = await analyzeWithCache(
        input,
        input.tarball,
        input.tarballDigest,
        logger,
      );
    } catch (error) {
      // A malformed archive becomes immutable blocking evidence inside the
      // evaluator; it is not a transient job failure.
      if (!(error instanceof ArchiveError)) throw error;
    }
  }

  let previous: ArtifactAnalysis | null = null;
  let previousUnavailable = false;
  if (input.previous) {
    if (input.previous.tarball) {
      try {
        previous = await analyzeWithCache(
          input,
          input.previous.tarball,
          input.previous.tarballDigest,
          logger,
        );
      } catch (error) {
        previousUnavailable = true;
        logger.error(
          {
            releaseId: input.releaseId,
            previousVersion: input.previous.version,
            error: error instanceof Error ? error.message : String(error),
          },
          "previous release artifact analysis failed; the audit diff will be incomplete",
        );
      }
    } else {
      previousUnavailable = true;
    }
  }

  const startedAt = new Date();
  const staticResult = await evaluateStaticAudit(
    {
      packageName: input.packageName,
      version: input.version,
      publisher: input.publisher,
      manifest: input.manifest,
      intent: input.intent,
      tarball: input.tarball,
      policy: input.policy,
      previous: input.previous
        ? {
            version: input.previous.version,
            publisher: input.previous.publisher,
            manifest: input.previous.manifest,
            tarball: input.previous.tarball,
          }
        : null,
      firstRelease: input.firstRelease,
      scopeKey: input.scopeKey,
    },
    current
      ? {
          current,
          previous,
          previousUnavailable,
        }
      : undefined,
  );

  let deterministicResult = staticResult;
  let sandbox: SandboxResult | null = null;
  if (input.sandbox && staticResult.policyResult !== "block") {
    try {
      sandbox = await input.sandbox(input.tarball);
      deterministicResult = withSandbox(staticResult, sandbox);
    } catch (error) {
      deterministicResult = withSandboxFailure(staticResult, error);
    }
  }

  let llmReview: LlmAuditReview | null = null;
  const llmFailureSignals: Signal[] = [];
  if (input.llm && deterministicResult.policyResult !== "block") {
    try {
      llmReview = await input.llm.review({
        packageName: input.packageName,
        version: input.version,
        intent: input.intent,
        changeSet: deterministicResult.changeSet,
        signals: deterministicResult.signals,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      logger.error(
        {
          releaseId: input.releaseId,
          backend: input.llm.id,
          error: message,
        },
        "LLM review failed; continuing with deterministic evidence",
      );
      llmFailureSignals.push(llmUnavailableSignal(input.llm.id, message));
    }
  }

  const nameSignals = detectNameSignals(
    input.packageName,
    input.existingPackageNames ?? [],
  );

  const result = mergeLlmReview(
    deterministicResult,
    llmReview,
    {
      policy: input.policy,
      intent: input.intent,
      firstRelease: input.firstRelease,
      previousUnavailable,
      packageName: input.packageName,
      scopeKey: input.scopeKey,
      diffFiles: deterministicResult.policyMetrics?.diffFiles,
      diffLines: deterministicResult.policyMetrics?.diffLines,
    },
    [...llmFailureSignals, ...nameSignals],
  );

  return { result, llmReview, sandbox, startedAt };
}

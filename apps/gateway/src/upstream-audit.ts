import { createHash } from "node:crypto";
import semver from "semver";
import type { PolicyResult, RiskTier, SafetyVerdict, IntentVerdict, Signal } from "@veripack/shared";
import type { Config } from "./config.js";
import type { Db } from "./db.js";
import { getCachedArtifact, putCachedArtifact } from "./audit/cache.js";
import {
  analyzeStaticArtifact,
  type ArtifactAnalysis,
} from "./audit/static.js";
import { runAudit } from "./audit/run.js";
import {
  evaluatePolicy,
  parseAuditPolicy,
  type AuditPolicy,
} from "./audit/policy.js";
import type { NpmVersionManifest } from "./npm/payload.js";
import { getActivePolicy } from "./policy-store.js";

export interface UpstreamAuditResult {
  digest: string;
  status: "audited" | "blocked";
  safetyVerdict: SafetyVerdict;
  intentVerdict: IntentVerdict;
  riskTier: RiskTier;
  policyResult: PolicyResult;
  signals: Signal[];
  changeSet: Record<string, unknown>;
  summary: string;
}

interface UpstreamAuditRow {
  tarball_digest: string;
  status: "audited" | "blocked";
  safety_verdict: SafetyVerdict;
  intent_verdict: IntentVerdict;
  risk_tier: RiskTier;
  policy_result: PolicyResult;
  signals: Signal[];
  change_set: Record<string, unknown>;
  summary: string;
  policy_version: string;
}

function digest(tarball: Buffer): string {
  return createHash("sha256").update(tarball).digest("hex");
}

function publicPolicy(policy: AuditPolicy): AuditPolicy {
  return {
    ...policy,
    // Public packages have no trusted local baseline or publisher workflow.
    // They are still blocked on deterministic critical evidence; medium/high
    // findings remain visible in the audit result. The safety floor (intent,
    // critical findings, incomplete diffs) still applies.
    firstRelease: { review: false },
    autoApproval: { ...policy.autoApproval, enabled: false },
  };
}

async function analyze(
  db: Db,
  requestedPackageName: string,
  versionLabel: string,
  tarball: Buffer,
  config: Config,
  policy: AuditPolicy,
): Promise<{ digest: string; result: UpstreamAuditResult }> {
  const tarballDigest = digest(tarball);
  const cacheKey = {
    scopeKey: "public",
    tarballDigest,
    engineVersion: config.AUDIT_ENGINE_VERSION,
  };
  let artifact: ArtifactAnalysis | null = await getCachedArtifact(db, cacheKey);
  if (!artifact) {
    artifact = await analyzeStaticArtifact(tarball);
    await putCachedArtifact(db, cacheKey, artifact).catch(() => undefined);
  }

  const packageJson = artifact.inventory.packageJson;
  const packageName = typeof packageJson?.name === "string" ? packageJson.name : "unknown";
  const version = typeof packageJson?.version === "string" ? packageJson.version : "unknown";
  const upstreamPolicy = publicPolicy(policy);
  if (
    !packageJson ||
    packageName !== requestedPackageName ||
    !semver.valid(version) ||
    (semver.valid(versionLabel) && version !== versionLabel)
  ) {
    const signal: Signal = {
      type: "upstream_manifest_mismatch",
      ruleId: "upstream-manifest-mismatch",
      severity: "critical",
      source: "deterministic",
      message: "The upstream tarball manifest is missing, invalid, or names a different package.",
      evidence: {
        requestedPackageName,
        archivePackageName: packageName,
        versionLabel,
      },
    };
    return {
      digest: tarballDigest,
      result: {
        digest: tarballDigest,
        status: "blocked",
        safetyVerdict: "block",
        intentVerdict: "mismatch",
        riskTier: "critical",
        policyResult: "block",
        signals: [signal],
        changeSet: { upstream: true, versionLabel },
        summary: signal.message,
      },
    };
  }
  const { result: staticResult } = await runAudit({
    packageName,
    version,
    publisher: "upstream:npm",
    manifest: packageJson as NpmVersionManifest,
    intent: "Public upstream package artifact fetched through Veripack.",
    tarball,
    tarballDigest,
    previous: null,
    firstRelease: false,
    policy: upstreamPolicy,
    scopeKey: "public",
    engineVersion: config.AUDIT_ENGINE_VERSION,
    cache: null,
    sandbox: null,
    llm: null,
    prepared: { current: artifact },
  });
  const result: UpstreamAuditResult = {
    digest: tarballDigest,
    status: staticResult.policyResult === "block" ? "blocked" : "audited",
    safetyVerdict: staticResult.safetyVerdict,
    intentVerdict: staticResult.intentVerdict,
    riskTier: staticResult.riskTier,
    policyResult: staticResult.policyResult,
    signals: staticResult.signals,
    changeSet: staticResult.changeSet,
    summary: staticResult.summary,
  };
  return { digest: tarballDigest, result };
}

export async function auditUpstreamTarball(
  db: Db,
  packageName: string,
  versionLabel: string,
  tarball: Buffer,
  config: Config,
): Promise<UpstreamAuditResult> {
  const tarballDigest = digest(tarball);
  const fallback = parseAuditPolicy(
    config.AUDIT_POLICY_VERSION,
    config.AUDIT_POLICY_JSON,
  );
  const policy = (await getActivePolicy(db, config.ORG_ID, fallback)).active;
  const currentPolicyVersion = publicPolicy(policy).version;

  // Evidence lookup ignores the policy version: a hit under an older policy
  // is re-evaluated against the current policy instead of being served stale.
  const cached = await db.query<UpstreamAuditRow>(
    `select tarball_digest, status, safety_verdict, intent_verdict,
            risk_tier, policy_result, signals, change_set, summary,
            policy_version
       from upstream_audits
      where tarball_digest = $1
        and package_name = $2
        and version = $3
        and engine_version = $4
        and ruleset_version = $5
        and intel_version = $6
        and expires_at > now()
      order by created_at desc
      limit 1`,
    [
      tarballDigest,
      packageName,
      versionLabel,
      config.AUDIT_ENGINE_VERSION,
      config.AUDIT_RULESET_VERSION,
      config.AUDIT_INTEL_VERSION,
    ],
  );
  const existing = cached.rows[0];
  if (existing) {
    if (existing.policy_version === currentPolicyVersion) {
      return {
        digest: existing.tarball_digest,
        status: existing.status,
        safetyVerdict: existing.safety_verdict,
        intentVerdict: existing.intent_verdict,
        riskTier: existing.risk_tier,
        policyResult: existing.policy_result,
        signals: existing.signals,
        changeSet: existing.change_set,
        summary: existing.summary,
      };
    }

    const evaluation = evaluatePolicy(
      {
        signals: existing.signals,
        intent: "Public upstream package artifact fetched through Veripack.",
        firstRelease: false,
        previousUnavailable: existing.signals.some(
          (signal) => signal.type === "previous_artifact_unavailable",
        ),
        packageName,
        scopeKey: "public",
      },
      publicPolicy(policy),
    );
    const recomputed: UpstreamAuditResult = {
      digest: existing.tarball_digest,
      status: evaluation.policyResult === "block" ? "blocked" : "audited",
      safetyVerdict: evaluation.safetyVerdict,
      intentVerdict: existing.intent_verdict,
      riskTier: evaluation.riskTier,
      policyResult: evaluation.policyResult,
      signals: existing.signals,
      changeSet: existing.change_set,
      summary: evaluation.summary,
    };
    await insertUpstreamAudit(db, config, packageName, versionLabel, recomputed);
    return recomputed;
  }

  const { result } = await analyze(
    db,
    packageName,
    versionLabel,
    tarball,
    config,
    policy,
  );
  await insertUpstreamAudit(db, config, packageName, versionLabel, result);
  return result;
}

async function insertUpstreamAudit(
  db: Db,
  config: Config,
  packageName: string,
  versionLabel: string,
  result: UpstreamAuditResult,
): Promise<void> {
  const fallback = parseAuditPolicy(
    config.AUDIT_POLICY_VERSION,
    config.AUDIT_POLICY_JSON,
  );
  const policy = (await getActivePolicy(db, config.ORG_ID, fallback)).active;
  await db.query(
    `insert into upstream_audits (
       tarball_digest, package_name, version, engine_version, ruleset_version,
       intel_version, policy_version, status, safety_verdict, intent_verdict,
       risk_tier, policy_result, signals, change_set, summary, expires_at
     ) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
               now() + ($16::text || ' days')::interval)
     on conflict (tarball_digest, package_name, version, engine_version,
                  ruleset_version, intel_version, policy_version)
       do update set status = excluded.status,
                     safety_verdict = excluded.safety_verdict,
                     intent_verdict = excluded.intent_verdict,
                     risk_tier = excluded.risk_tier,
                     policy_result = excluded.policy_result,
                     signals = excluded.signals,
                     change_set = excluded.change_set,
                     summary = excluded.summary,
                     expires_at = excluded.expires_at`,
    [
      result.digest,
      packageName,
      versionLabel,
      config.AUDIT_ENGINE_VERSION,
      config.AUDIT_RULESET_VERSION,
      config.AUDIT_INTEL_VERSION,
      publicPolicy(policy).version,
      result.status,
      result.safetyVerdict,
      result.intentVerdict,
      result.riskTier,
      result.policyResult,
      JSON.stringify(result.signals),
      JSON.stringify(result.changeSet),
      result.summary,
      String(config.UPSTREAM_AUDIT_TTL_DAYS),
    ],
  );
}

/** Deletes cached upstream evidence so the next fetch re-audits from scratch. */
export async function forceUpstreamReaudit(
  db: Db,
  input: { packageName: string; tarballDigest?: string | null },
): Promise<number> {
  const result = await db.query<{ tarball_digest: string }>(
    `delete from upstream_audits
      where package_name = $1
        and ($2::text is null or tarball_digest = $2)
      returning tarball_digest`,
    [input.packageName, input.tarballDigest ?? null],
  );
  return result.rows.length;
}

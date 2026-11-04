export type ReleaseStatus =
  | "pending"
  | "approved"
  | "rejected"
  | "yanked"
  | "quarantined"
  | "overridden";

export type SafetyVerdict = "clear" | "review" | "block" | "unknown";

export type IntentVerdict = "matches" | "mismatch" | "unknown";

export type RiskTier = "low" | "medium" | "high" | "critical";

export type PolicyResult = "pass" | "warn" | "block";

export type PolicyVerdict = "clear" | "review" | "block";
export type PolicyReviewAuthority = "reviewer" | "admin";
export type PolicyHighRiskAuthority = PolicyReviewAuthority | "two_reviewers";

/**
 * V1 team policy. The safety floor is deliberately absent: critical
 * deterministic findings, missing intent, an unavailable previous artifact, and
 * binary/obfuscated content are enforced by the evaluator and cannot be
 * configured away here.
 */
export interface AuditPolicy {
  version: string;
  firstRelease: { review: boolean };
  autoApproval: {
    enabled: boolean;
    maxDiffFiles: number;
    maxDiffLines: number;
    allowDocsOnly: boolean;
    allowVersionOnly: boolean;
  };
  review: {
    medium: PolicyReviewAuthority;
    high: PolicyHighRiskAuthority;
  };
  provenance: { required: boolean };
  installScripts: { allow: string[]; deny: string[] };
  packages: {
    banned: string[];
    requiredVerdicts: Record<string, PolicyVerdict>;
  };
  scopes: {
    requiredVerdicts: Record<string, PolicyVerdict>;
    twoReviewer: string[];
  };
  yank: { requireReview: boolean };
  quarantine: { requireReview: boolean };
  selfApproval: { enabled: boolean; maxRiskTier: "medium" };
  revocation: { flagBelowInstalls: number; withinDays: number };
}

export type SignalSource = "deterministic" | "llm";

export type SignalSeverity = "info" | "low" | "medium" | "high" | "critical";

export interface Signal {
  type: string;
  severity: SignalSeverity;
  source: SignalSource;
  message: string;
  ruleId?: string;
  evidence?: Record<string, unknown>;
}

export type ApprovalDecision =
  | "approved"
  | "rejected"
  | "yanked"
  | "quarantined"
  | "overridden";

export type ReviewerType = "human" | "system";

export interface Approval {
  id: string;
  releaseId: string;
  auditId: string | null;
  reviewerId: string;
  reviewerType: ReviewerType;
  reviewerRole: string | null;
  decision: ApprovalDecision;
  reason: string | null;
  policyVersion: string | null;
  createdAt: string;
}

export interface AuditEvent {
  id: string;
  orgId: string;
  actor: string;
  action: string;
  subject: string | null;
  metadata: Record<string, unknown>;
  createdAt: string;
}

export interface AuditReport {
  id: string;
  releaseId: string;
  engineVersion: string;
  policyVersion: string;
  llmReview: LlmReview | null;
  safetyVerdict: SafetyVerdict;
  intentVerdict: IntentVerdict;
  riskTier: RiskTier;
  policyResult: PolicyResult;
  signals: Signal[];
  changeSet: Record<string, unknown>;
  summary: string | null;
  startedAt: string;
  finishedAt: string;
  createdAt: string;
}

export interface LlmEvidenceCitation {
  source: "change_set" | "signal";
  path: string;
  explanation: string;
}

export interface LlmReview {
  backend: string;
  safetyVerdict: SafetyVerdict;
  intentVerdict: IntentVerdict;
  riskTier: RiskTier;
  confidence: number | null;
  citations: LlmEvidenceCitation[];
  model: string;
  promptHash: string;
  sampling: Record<string, unknown>;
  tokenCost: number | null;
}

export interface ReleaseSummary {
  id: string;
  orgId: string;
  packageName: string;
  version: string;
  tarballDigest: string;
  integrity: string | null;
  shasum: string | null;
  status: ReleaseStatus;
  publisher: string;
  intent: string | null;
  createdAt: string;
  updatedAt: string;
  riskTier: RiskTier | null;
  safetyVerdict: SafetyVerdict | null;
  intentVerdict: IntentVerdict | null;
  policyResult: PolicyResult | null;
}

export interface ReleaseDetail extends ReleaseSummary {
  manifest: Record<string, unknown>;
  audit: AuditReport | null;
  audits: AuditReport[];
  approvals: Approval[];
  events: AuditEvent[];
}

export interface ReleaseListResponse {
  releases: ReleaseSummary[];
}

export interface ReleaseDetailResponse {
  release: ReleaseDetail;
}

export interface ApiError {
  error: string;
  releaseId?: string;
  status?: ReleaseStatus;
}

export const RELEASE_STATUSES: ReleaseStatus[] = [
  "pending",
  "approved",
  "rejected",
  "yanked",
  "quarantined",
  "overridden",
];

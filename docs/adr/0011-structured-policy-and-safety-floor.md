# Structured policy model with a non-configurable safety floor

Status: accepted 2026-11-04 (V1 Phase 2)

The five-boolean `AuditPolicy` is replaced with a structured, strictly parsed
policy:

- `firstRelease: { review }`
- `autoApproval: { enabled, maxDiffFiles, maxDiffLines, allowDocsOnly,
  allowVersionOnly }`
- `review: { medium: "reviewer" | "admin", high: "reviewer" | "admin" |
  "two_reviewers" }`
- `provenance: { required }`
- `installScripts: { allow, deny }`
- `packages: { banned, requiredVerdicts }`
- `scopes: { requiredVerdicts, twoReviewer }`
- `yank: { requireReview }`, `quarantine: { requireReview }`
- `selfApproval: { enabled, maxRiskTier: "medium" }`

Parsing uses a strict Zod schema: unknown keys and wrong types are rejected for
both database policies and `AUDIT_POLICY_JSON` at startup. Policies are
canonicalized (sorted keys, sorted lists) and diffed semantically; a semantic
change with an unchanged version is rejected.

The safety floor is a code constant (`SAFETY_FLOOR` in
`apps/gateway/src/audit/policy.ts`), never a policy field, so no policy payload
can disable it:

- deterministic critical findings always block;
- no auto-approval when the previous artifact is unavailable;
- no auto-approval for binary/WASM/native-addon content or
  obfuscation/minification;
- `trust.intent` is required for private releases (missing intent is at least
  medium risk and never auto-approves).

Policy control is asymmetric. Tightening activates immediately with a single
admin. Loosening creates a `policy_change_requests` row with a visible diff and
a recorded reason, and completes only with a second admin or after a 24-hour
cooling-off; requests left open past a seven-day grace window expire.
Activation writes `policy_versions`, `active_policy_versions`, and an audit
event in one transaction, and never changes approved releases; the impact
report and dry-run cover pending releases only.

## Legacy mapping

Pre-V1 rows may hold the five-boolean shape. `migrateLegacyAuditPolicy` maps
them onto the structured model on read; new writes are always v2.

| Legacy field | V2 mapping |
|---|---|
| `requireFirstReleaseReview` | `firstRelease.review` |
| `autoApproveLowRisk` | `autoApproval.enabled` (diff limits and docs/version toggles take the v2 defaults) |
| `requireReleaseIntent` | dropped: now a safety-floor rule |
| `requireCompleteDiffForAutoApproval` | dropped: now a safety-floor rule |
| `blockCriticalFindings` | dropped: now a safety-floor rule |

Fields with no legacy equivalent (`review`, `provenance`, `installScripts`,
`packages`, `scopes`, `yank`, `quarantine`, `selfApproval`) take the v2
defaults. A payload mixing legacy and v2 fields is not treated as legacy and
fails strict parsing.

# Package Trust

Terms for a private trusted registry that audits package releases for publishers
and enforces policy over gateway-mediated publishes and installs. V1 is an
npm-compatible private registry, not a registry-agnostic overlay.

## Language

**Release**:
A specific published artifact of a package, identified by version and content hash. Audit and revocation act on a release, not on a version label.
_Avoid_: Version, build

**Audit**:
A per-release judgment about whether the changes are safe and intended, backed by evidence. A scan collects signals; an audit interprets them.
_Avoid_: Scan, check

**Capability**:
Something a package's code can do when executed, such as network access, filesystem writes, child processes, environment reads, or eval. Capabilities are inferred unless a manifest declares them.
_Avoid_: Permission

**Permission**:
An enforced runtime allowance granted to code. A permission is a policy decision; a capability is an observation.
_Avoid_: Capability

**Risk-proportional friction**:
The amount of interruption scales with the risk of the release. Low-risk
follow-ups are silent; medium/high-risk releases require review. It applies at
publish time (the gate) and install time (the registry's developers).
_Avoid_: Warning fatigue, safety score

**Audit verdict**:
The audit's overall assessment of whether a release's changes are safe and
intended, presented with its evidence. It combines deterministic signals and
optional LLM assistance; it is advisory unless a deterministic signal or team
policy makes it blocking.
_Avoid_: Vibe check, safety score

**Publisher-side audit**:
An audit initiated by the publisher for a release they publish, rather than by a consumer or registry.
_Avoid_: Self-audit, pre-publish scan

**Pre-flight audit**:
A publisher-side audit run before the release is published.
_Avoid_: Pre-publish check

**Consumer-side audit**:
An audit initiated by a consumer or registry for a release they are about to install or serve.
_Avoid_: Install-time scan

**Safety**:
Whether a release contains behavior that is malicious or dangerous to its consumers.
_Avoid_: Trustworthiness, vibe

**Intent**:
Whether a release's changes are consistent with the package's purpose and the publisher's stated reason for the release.
_Avoid_: Trustworthiness, vibe

**Yank**:
Block all gateway downloads of a release, including downloads by existing
lockfiles, while retaining the release in audit history. The release is hidden
from packuments and is never served through the gateway, even if the backend
still holds the tarball.
_Avoid_: Revoke, unpublish

**Quarantine**:
An emergency block applied by an admin that stops all resolutions of a release,
including existing lockfiles. A quarantined release can later be terminally
rejected with a reason.
_Avoid_: Revoke, yank

**Deprecate**:
Keep a release installable but warn consumers that it should not be used. This is
an npm concept, not a V1 Veripack operation; yank is the supported withdrawal
path.
_Avoid_: Revoke

**Delete (unpublish)**:
Remove a release's artifact from a registry. This breaks reproducibility and is
reserved for a short window with no dependents. It is not a V1 Veripack
operation; yank is the supported withdrawal path.
_Avoid_: Revoke, yank

**Publisher**:
The identity that uploaded a specific release, often a CI workflow or OIDC token.
_Avoid_: Maintainer, author

**Maintainer**:
The person or organization accountable for a package over time.
_Avoid_: Publisher, owner

### Audit model

**Signal**:
A single observed fact or finding from an audit, tagged deterministic or LLM-assisted, with a severity and evidence.
_Avoid_: Alert, issue

**Safety verdict**:
The audit's judgment about whether a release contains malicious or dangerous behavior: clear, review, block, or unknown.
_Avoid_: Score, risk rating

**Intent verdict**:
The audit's judgment about whether the release's changes match the publisher's declared intent: matches, mismatch, or unknown.
_Avoid_: Vibe check

**Risk tier**:
The severity band used to choose friction and approval authority: low, medium, high, or critical.
_Avoid_: Score

**Policy result**:
The team policy's decision for a release: pass, warn, or block.
_Avoid_: Verdict

**Release intent**:
The publisher's stated reason for a release, compared against the actual change
set. V1 makes `trust.intent` the canonical field; a publish wrapper writes it
into the packed manifest before hashing and auditing.
_Avoid_: Changelog, release note

**Structured change set**:
The audit's machine-readable summary of what changed between releases: files, manifest, dependencies, scripts, capabilities, and binaries.
_Avoid_: Diff

**Audit run**:
One execution of the audit pipeline for a release: cached artifact analysis, deterministic rules, optional sandbox, and optional LLM review, ending in a single audit record. The worker, pre-flight, and upstream audit all enter through the same run.
_Avoid_: Audit job, scan

**Static rule**:
A deterministic check over the structured change set that emits a signal. A static rule never reads the archive or evaluates policy.
_Avoid_: Check, validator

**Pending release**:
A release stored by the registry but not installable until the publish gate approves it.
_Avoid_: Draft, staged release

**Installable release**:
A release the registry resolves for installs: approved or overridden, and
replayed successfully. A yanked release is not installable and is not
downloadable, including for existing lockfiles.
_Avoid_: Live version, available release

**Reviewer**:
A person authorized to approve or reject a pending medium/high release within
policy. A reviewer cannot change policy, quarantine, or override.
_Avoid_: Approver, admin

**Current audit**:
The immutable audit selected for a pending decision. It must have been produced
under the currently active policy; a stale audit forces re-audit or hold.
_Avoid_: Latest scan

**Audit cache**:
The reuse of source-free artifact evidence for an identical tarball digest and
engine version. Public upstream audit results use a separate cache keyed by
digest, package/version, engine, ruleset/intel, and policy, with a TTL.
_Avoid_: Memoization

**Policy**:
The versioned set of team rules and overrides that turns audit verdicts into pass, warn, or block.
_Avoid_: Rules, config

**Approval**:
A recorded decision by a reviewer or admin. Reviewers approve or reject
medium/high releases within policy; admins handle overrides, quarantine, and
policy. Publishers may yank their own approved releases.
_Avoid_: Sign-off, review

**Release lifecycle**:
The path a release takes from pending through a decision to installable, yanked, or quarantined, including replay. Every decision crosses the same seam.
_Avoid_: Workflow, state machine

**Audit event**:
An append-only record of a state change or decision in the registry, such as
publish, audit, approve, reject, yank, quarantine, override, or policy change.
_Avoid_: Log entry

**Install event**:
An append-only record of an allowed or blocked install attempt: actor, package,
version, digest, decision, and timestamp. It is separate from audit events and
is written synchronously before a tarball is served.
_Avoid_: Access log

**Blocklist**:
A package/version/digest entry with an append-only reason. It is checked before
the audit cache, packument filtering, and tarball serving, and it forces
re-audit when added or when the engine/policy changes.
_Avoid_: Denylist

**Attestation**:
A signed, machine-readable record of an audit and its verdicts, bound to a
release digest. Public attestations are V2; V1 audit records are internal
evidence.
_Avoid_: Certificate, badge

**Agent panel**:
A set of specialized review agents whose combined advisory decision is
bounded by risk tier and policy. Implemented in the V2 layer: agents post
append-only recommendations and a unanimous panel speaks with one advisory
voice, but agents never approve a release — humans decide.
_Avoid_: AI reviewer, auto-approver

**Human escalation**:
The requirement that a reviewer or admin makes the final decision for high risk,
that critical risk requires an explicit admin override with a reason, or that a
person decides when the evidence is incomplete.
_Avoid_: Manual review

### Registry

**Private trusted registry**:
A team's default JavaScript package registry, compatible with npm, pnpm, and Bun,
that proxies public packages, hosts private packages, and audits every private
release before it becomes installable. Public upstream packages are scanned and
blocked on critical findings, not approved.
_Avoid_: Overlay registry, proxy registry, private registry

**Proxied package**:
A public package fetched from an upstream registry and cached by the private trusted registry.
_Avoid_: Mirrored package, upstream package

**Private package**:
A package hosted by the private trusted registry and visible only to the team.
_Avoid_: Internal package, local package

**Publish gate**:
The policy point where a release must pass audit before it becomes installable from the registry.
_Avoid_: Audit check, CI check

**Release diff**:
The change between the previous release of a package and the new release.
_Avoid_: Package diff

**Upgrade diff**:
The change a consumer sees when moving from the version in their lockfile to a new release.
_Avoid_: Version diff

# M2 starts with versioned policy and content-addressed artifact evidence

Status: accepted; amended 2026-11-04 by the V1 design contract

M2 keeps deterministic analysis useful without requiring a networked model. The
static worker produces source-free artifact evidence that can be reused by
tarball digest, while the current release context and team policy are evaluated
again for every private release. The artifact-evidence cache is
deployment-scoped and includes the analyzer engine version so analyzer changes
never silently reuse stale evidence.

The public upstream audit cache is separate. Its key includes the tarball digest,
package/version, engine version, ruleset/intel version, and policy version. It has
a configurable TTL (default seven days), supports an admin force-re-audit per
package/digest, and is checked only after the blocklist. Private audits are
immutable and are not reused across deployments. A pending decision that lacks
an audit under the currently active policy forces re-audit or hold.

Policy decisions are represented by a versioned policy object. The policy
version is stored on the audit and on system or human approval records. The
default policy remains conservative: first releases require review, critical
deterministic findings block, and only complete low-risk follow-up audits can
auto-approve.

The cache stores inventory metadata, hashes, parsed manifest data, dependency
install-script provenance, and AST findings, but not analyzed source text. A
cache hit therefore avoids archive parsing and AST work without making private
source code a durable database artifact or dropping provenance signals. Cache
failure is non-fatal to an audit; a release can still be audited and the cache
can be repopulated later.

The LLM boundary is a separate interface. Deterministic-only mode is the
default and is valid. Providers receive structured change sets, release intent,
and deterministic evidence, not full tarballs or source text by default. Selected
hunks require an explicit per-org opt-in with a separate privacy contract. Model,
prompt, sampling, and evidence metadata are recorded alongside the audit.

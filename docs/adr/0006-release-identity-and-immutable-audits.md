# A release is its tarball digest; audits are immutable

Status: accepted; amended 2026-11-04 by the V1 design contract

A release is identified by its tarball digest, not by its version label. Audits, signals, approvals, and audit events are immutable or append-only; policy is versioned. This makes the audit cache safe (same digest, same artifact), makes compliance evidence credible, and prevents a registry from silently changing the meaning of a version. Versions are labels; content is identity.

A release may have multiple immutable audits. Uniqueness is
`(release_id, engine_version, policy_version)`, and a current-audit pointer
selects the audit a pending decision uses. Approvals reference the audit id and
policy version. A pending decision requires an audit produced under the currently
active policy; a stale audit forces re-audit or hold.

## Consequences

- Republishing a version with different content is rejected, not overwritten.
- Cached public upstream audits are keyed by digest, package/version, engine,
  ruleset/intel, and policy, with a TTL; private audits stay deployment-scoped
  and are never reused across deployments.
- A yank or quarantine changes a release's policy status, not its content.
- Policy activation uses a separate pointer, so activating a new policy never
  mutates an historical policy version.
- Append-only enforcement is at the database layer, not only in application code.

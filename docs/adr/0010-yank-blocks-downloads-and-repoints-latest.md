# Yank blocks downloads and repoints latest

Status: accepted; amended 2026-11-04 by the V1 design contract

A yank changes a release's policy status, not its tarball. The gateway must
never serve a yanked release, even if Verdaccio still holds the tarball. A
direct tarball request returns `404` and writes a blocked install event. The
packument omits the version so new resolutions cannot select it, and `latest`
moves to the highest remaining stable installable version; if no installable
version remains, the tag is removed.

This is stricter than npm's `deprecate`, which keeps a version installable with
a warning, and stricter than the earlier V1 design, which kept a yanked tarball
available to existing lockfiles. The team has decided that a withdrawn release
must not be distributed through the gateway at all. Existing lockfiles that pin
a yanked version fail closed; that is the intended behavior.

## Consequences

- New `npm install pkg` resolutions skip the yanked version.
- Existing lockfiles that pin it cannot download it through the gateway.
- A yanked version no longer appears in `versions`, `dist-tags`, or `time`.
- If the last installable version is yanked, the package has no `latest` tag
  until another version is approved.
- A failed yank replay to Verdaccio is a reconciliation alert and a retryable
  job, not a serving condition. The gateway remains the enforcement point.
- Un-yank is admin-only and requires a fresh audit and a verified replay before
  the release becomes installable again.

# Private trusted registry, not a public registry or consumer scanner

Status: accepted; amended 2026-11-04 by the V1 design contract

npm's public registry cannot give a team control over revocation, naming, or install policy. We will build a private trusted registry for teams that publish packages: a JavaScript package registry compatible with npm, pnpm, and Bun that proxies public npm, hosts private packages, audits every private release, and gates private releases before they become installable. Public upstream packages are scanned and blocked on critical findings at download time; they are not approved. A new public registry or a standalone consumer scanner is out of scope; the promise is "audited releases for teams that publish and consume through the registry," not "the public package ecosystem is safe for everyone."

## Considered options

- **Audit API sidecar**: lowers adoption friction, but the audit is voluntary and the policy problems remain advisory.
- **Public registry replacement**: solves the problems globally, but requires winning a namespace and publisher network against npm.
- **Private trusted registry**: solves all nine problems for the team, with a clear buyer and no public network-effect fight.

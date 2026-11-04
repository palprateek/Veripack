# Veripack — Trusted Package Release Registry

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

> **A private JavaScript package registry compatible with npm, pnpm, and Bun
> that audits every private release before it becomes installable and scans
> public upstream packages at download time.**

Veripack is a security-first publish gate for teams that use the JavaScript package
ecosystem. It works with the existing npm protocol, so developers can keep
using **npm, pnpm, or Bun** while the registry captures each release, analyzes
it without executing package code, and makes an evidence-backed decision before
the artifact is distributed.

This repository contains an implementation baseline of the trusted-release
loop. The V1 design contract is in [`docs/v1-spec.md`](docs/v1-spec.md); the
baseline does not yet satisfy every requirement in that contract. See
[Project status](#project-status). The core loop is:

1. A publisher runs a normal package publish command.
2. Veripack stores the tarball as a pending release.
3. Static analysis produces file inventories, hashes, diffs, capabilities, and
   deterministic risk signals.
4. Policy decides whether the release is auto-approved, held for review, or
   blocked.
5. Only approved releases are replayed into the private registry backend.
6. Clients install approved releases through the same gateway.

## Why this matters

Package managers are excellent distribution protocols, but they are not release
review systems. A package can change its install scripts, capabilities, binary
contents, or dependency surface between two versions, while a consumer sees
only a version number and a prompt to install.

Veripack adds a trusted control plane without replacing npm tooling:

- **Every private release is gated**, including first releases and release diffs.
- **Pending releases are not installable.** They never reach Verdaccio.
- **Upstream releases are scanned at download time.** Public npm tarballs are
  spooled to a bounded temp file or S3 object, deterministically audited, and
  then streamed to clients; the digest/policy result is cached for later
  installs. Critical findings block; high/medium findings are served as
  scanned, not approved.
- **Evidence comes first.** The verdict is backed by structured findings.
- **Risk controls friction.** Low-risk follow-ups can auto-approve when the
  safety floor permits; higher-risk releases wait for a human.
- **Deterministic critical findings cannot be disabled by policy.** An admin may
  override a specific release with a recorded reason.
- **Yank and quarantine are explicit states** with append-only decisions. A
  yanked release is never downloadable through the gateway.
- **Package code is never executed during static analysis.**

## 60-second demo

The repository includes three intentionally small example packages:

| Example | Expected result |
|---|---|
| `examples/safe-package` | First release waits for review; an unchanged follow-up auto-approves |
| `examples/review-package` | Benign lifecycle script requires human review |
| `examples/risky-package` | Remote download/execute behavior is deterministically rejected |

After starting the local stack, run:

```bash
pnpm smoke
```

The smoke test publishes fresh versions, waits for audits, approves the review
cases, verifies successful installs, and confirms the risky package cannot be
installed.

## Architecture

```text
                         ┌──────────────────────┐
 npm / pnpm / Bun ──────▶│  Veripack Gateway :4874  │◀──── Dashboard :3000
       publish/install    │ auth · gate · proxy  │       OIDC session
                         └───────┬───────┬──────┘
                                 │       │
                         ┌───────▼───┐ ┌─▼──────────────┐
                         │ PostgreSQL │ │ S3 / S3Mock     │
                         │ metadata + │ │ tarballs +      │
                         │ pg-boss    │ │ payloads        │
                         └───────┬────┘ └────────────────┘
                                 │ audit queue
                         ┌───────▼────────────┐
                         │ Static audit worker │
                         │ policy + optional   │
                         │ evidence LLM review │
                         └───────┬────────────┘
                                 │ approved replay only
                         ┌───────▼────────────┐
                         │ Verdaccio :4873    │──────▶ public npm uplink
                         │ private backend    │
                         └────────────────────┘
```

The gateway is the only registry endpoint exposed to clients. Verdaccio is a
private npm protocol/storage layer. A pending or rejected tarball is stored in
S3/Postgres but is never replayed to Verdaccio. A yanked release is blocked at
the gateway even if Verdaccio still holds the tarball.

## Release lifecycle

```text
publish
   │
   ▼
pending ──▶ static audit ──▶ policy decision
                              │
              ┌───────────────┼────────────────┐
              ▼               ▼                ▼
          approved        pending           rejected
              │          human review           │
              ▼               │                ▼
          replayed       approve/reject   not installable
              │
              ▼
          installable
```

Release identity is the tarball digest. Audits, approvals, policy versions,
and audit events are persisted as immutable evidence. The supported states are:

`pending`, `approved`, `rejected`, `yanked`, `quarantined`, and `overridden`.

Yanked releases are hidden from packuments and are not downloadable through the
gateway, including for existing lockfiles. Quarantined releases are blocked for
every resolution.

## Baseline implementation

The bullets below describe the current baseline. The V1 contract in
[`docs/v1-spec.md`](docs/v1-spec.md) is implemented; see
[Project status](#project-status).

### Registry compatibility

- npm package publish `PUT` handling, including scoped package names.
- Packument and tarball proxying through the gateway.
- Approved replay to Verdaccio.
- Shared registry authentication configuration for npm, pnpm, and Bun.
- Yank/quarantine filtering for metadata and tarball resolution; yanked
  releases are never downloadable, including for existing lockfiles.
- Deterministic audit gating for public npm uplink tarballs before the response
  is served; the baseline buffers the tarball, which the V1 contract replaces
  with a bounded spool.

### Static auditing

- Safe tar extraction with traversal, size, file-count, and compression-ratio
  limits.
- Archive inventory and SHA-256 file hashes.
- Manifest extraction and validation.
- Structured release diffs against the previous release.
- JavaScript and TypeScript AST capability analysis without executing package
  code.
- Dependency install-script provenance from bundled manifests and lockfiles.
- Signals for lifecycle scripts, remote execution, capabilities, binaries/WASM,
  minification, source maps, dependency changes, archive integrity, and release
  metadata.

### Policy and review

- Separate safety, intent, risk-tier, and policy verdicts.
- First-release review by default.
- Low-risk follow-up auto-approval.
- Medium/high-risk human review.
- Deterministic critical findings block by default; the V1 safety floor makes
  this non-configurable.
- Versioned policy configuration through `AUDIT_POLICY_VERSION` and
  `AUDIT_POLICY_JSON`, plus an authenticated dashboard editor with immutable
  Postgres policy history.
- Scope/digest/engine-keyed artifact cache that excludes analyzed source text.
- Optional OpenAI-compatible LLM review using the structured change set and
  intent only; no source text by default.
- Citation grounding, prompt hash, model, sampling, confidence, and token
  metadata are persisted with the audit.

### Authentication and operations

- Generic OIDC JWT validation for gateway access.
- GitHub OAuth dashboard federation and GitHub Actions OIDC token exchange with
  repository/workflow allowlists and short-lived Veripack tokens.
- Publisher/admin roles, a single-tenant deployment key, and package scopes such
  as `@acme/*`.
- OIDC dashboard authorization-code flow with PKCE.
- Encrypted HttpOnly dashboard sessions and same-origin action protection; the
  V1 contract adds MFA, step-up, idle/absolute timeouts, and revocation.
- Explicit CORS origins, Helmet security headers, rate limits, request limits,
  and redacted authorization/cookie logs.
- Postgres-backed distributed rate limiting for multi-replica deployments.
- Prometheus metrics at `/metrics`, with a local Prometheus/Grafana compose
  stack.
- Optional network-disabled Docker/Podman sandbox execution, never invoked by
  static analysis unless explicitly enabled.
- `veripack audit` preflight CLI and reusable GitHub Action.
- `pnpm backup:restore-check` custom-format dump, S3 upload, and a baseline
  restore check; the V1 contract requires a separate backup bucket, inventory
  manifest, and digest verification.
- `/livez` and `/readyz` probes.
- Separate `gateway`, `worker`, and `all` process roles.
- TLS Postgres and non-auto-created S3 production guards.
- Streamed private tarball proxy responses; upstream tarballs are spooled
  to bounded temp files while hashing, never buffered unbounded.
- Production-oriented Dockerfiles for gateway and dashboard.

### V1 contract status

The V1 contract is implemented (phases P0–P9 of
[`docs/v1-implementation-plan.md`](docs/v1-implementation-plan.md)): multiple
immutable audits with a current-audit pointer and append-only evidence; the
structured policy model with a non-configurable safety floor and asymmetric
control; durable replay with lease takeover; the full lifecycle transition
set with reviewer authority, per-org self-approval, and two-reviewer
approvals; read/publish token scopes, per-repository GitHub federation with
protected refs; state-based yank blocking, install events, blocklist
precedence, Veripack-owned dist-tags, and missing-artifact holds; the full
upstream cache key with TTL and bounded spooled ingestion; verified backup
inventories, dual Verdaccio identities, the alert pack, and `veripack
registry rebuild`; server-side dashboard sessions with `__Host-` cookies,
admin MFA, and step-up; and the `veripack publish` wrapper with digest
idempotency. Claim approval, typosquat/collision detection, and the agent
panel were V2 in the original contract and are now implemented as the V2
layer: package name claims with admin approval, typosquat/collision signals,
an advisory agent panel (agents never approve; humans decide),
threshold-based revocation flagging, a `veripack run` npx-style CLI that
shows the audit before executing, and SIEM/S3 compliance exports. Cross-org
package sharing and multi-registry (non-JS) support remain future work.

## Supported clients

Veripack speaks the standard npm registry protocol.

| Client | Publish | Install | Auth mechanism |
|---|---:|---:|---|
| npm | Yes | Yes | `.npmrc` bearer token |
| pnpm | Fast follow | Yes | `.npmrc` bearer token |
| Bun | Yes | Yes | Standard registry/token configuration |

The V1 contract guarantees `npm publish` and `bun publish`; pnpm publish is a
fast follow. Install compatibility covers all three clients.

Example `.npmrc` for local development:

```ini
registry=http://localhost:4874
//localhost:4874/:_authToken=dev-token
always-auth=true
```

For production, replace `dev-token` with a short-lived OIDC access token or
CI-issued registry token. Configure the same registry URL and token for npm,
pnpm, and Bun. Do not commit `.npmrc` files containing real credentials.

## Local setup

### Requirements

- Node.js 20 or newer
- pnpm 10 or newer
- Docker with Docker Compose
- npm for the included smoke script
- Bun is optional for the Bun client check

### Start the development stack

From this `veripack/` directory:

```bash
cp .env.example .env
pnpm install
pnpm verdaccio:seed
pnpm infra:up
pnpm db:migrate
pnpm dev
```

Services:

| Service | URL |
|---|---|
| Dashboard | <http://localhost:3000> |
| Veripack gateway | <http://localhost:4874> |
| Verdaccio backend | <http://localhost:4873> |
| S3Mock | <http://localhost:9090> |
| PostgreSQL | `localhost:5432` |

The local profile uses static development tokens. It is not a production
configuration.

### Run the end-to-end demo

With the gateway running:

```bash
pnpm smoke
```

The script uses `REGISTRY_TOKEN` and `ADMIN_TOKEN` when supplied; otherwise it
uses the local `.env.example` development values:

```bash
REGISTRY_TOKEN=dev-token ADMIN_TOKEN=admin-token pnpm smoke
```

### Run a preflight audit from CI

The CLI packages a directory with `npm pack --ignore-scripts` and sends the
tarball to the non-persistent preflight endpoint. It never promotes a release:

```bash
VERIPACK_REGISTRY_URL=https://registry.example.com \
VERIPACK_REGISTRY_TOKEN="$VERIPACK_TOKEN" \
pnpm veripack audit . --fail-on block --json
```

Use the root `action.yml` from GitHub Actions to run the same check. The example
workflow in `.github/workflows/veripack-preflight.example.yml` obtains a short-lived
GitHub Actions OIDC token, exchanges it for a scoped Veripack token, and fails the
job on a blocking verdict.

The preflight result is advisory. The V1 contract adds a publish wrapper that
writes `trust.intent` into the packed manifest before hashing and uploads the
same audited bytes; the baseline CLI does not yet do this.

### Reset local state

```bash
pnpm infra:reset
pnpm infra:up
```

This removes local Postgres, Verdaccio, and S3Mock volumes.

## Manual package walkthrough

For the local static-auth profile, create a temporary npm configuration rather
than committing credentials into an example package:

```bash
cat >/tmp/veripack-demo.npmrc <<'EOF'
registry=http://localhost:4874
//localhost:4874/:_authToken=dev-token
always-auth=true
EOF
export NPM_CONFIG_USERCONFIG=/tmp/veripack-demo.npmrc
```

Use a short-lived production token instead of `dev-token` when testing a real
deployment.

### Safe package

```bash
cd examples/safe-package
npm publish --registry http://localhost:4874
```

The first release intentionally requires review. Approve it in the dashboard,
then publish another version. The unchanged-capability follow-up should be
low-risk, auto-approved, replayed, and installable.

### Review package

```bash
cd examples/review-package
npm publish --registry http://localhost:4874
```

Inspect the lifecycle script in the dashboard, provide a decision reason, and
approve the release if it is acceptable.

### Risky package

```bash
cd examples/risky-package
npm publish --registry http://localhost:4874
```

The package contains a remote download/execute pattern. The deterministic audit
rejects it and the gateway returns no installable version.

## API surface

All registry operations require a publisher token. Admin operations require an
administrator token or OIDC token with an admin role.

This table describes the baseline API. The V1 contract adds install-event,
blocklist, policy-impact, and registry-rebuild operations; see
[`docs/v1-spec.md`](docs/v1-spec.md).

| Method | Endpoint | Purpose |
|---|---|---|
| `PUT` | `/:package` | Store a publish as pending |
| `GET` | `/:package` | Return a filtered packument |
| `GET` | `/:package/-/:tarball` | Proxy an approved tarball |
| `GET` | `/-/whoami` | Validate registry identity |
| `GET` | `/livez` | Process liveness |
| `GET` | `/readyz` | Postgres and Verdaccio readiness |
| `GET` | `/health` | Operator health summary |
| `GET` | `/admin/releases` | List releases |
| `GET` | `/admin/releases/:id` | Read audit and decision detail |
| `POST` | `/admin/releases/:id/approve` | Approve/replay a release |
| `POST` | `/admin/releases/:id/reject` | Reject a pending release |
| `POST` | `/admin/releases/:id/yank` | Yank an approved release |
| `POST` | `/admin/releases/:id/quarantine` | Block all resolutions |
| `POST` | `/admin/releases/:id/replay` | Retry backend replay |
| `POST` | `/admin/releases/:id/audit` | Requeue a pending audit |
| `POST` | `/admin/releases/:id/sandbox` | Run an explicit isolated entrypoint check |
| `GET` | `/admin/policy` | Read active policy and history |
| `PUT` | `/admin/policy` | Activate a new immutable policy version |
| `POST` | `/-/veripack/preflight` | Run a non-persistent pre-publish audit |
| `POST` | `/-/auth/github/actions/exchange` | Exchange a GitHub Actions OIDC token |
| `POST` | `/-/auth/github/oauth/exchange` | Exchange a GitHub OAuth token |
| `GET` | `/metrics` | Prometheus-compatible operational metrics |

Example:

```bash
curl -H "Authorization: Bearer admin-token" \
  http://localhost:4874/admin/releases

curl -X POST \
  -H "Authorization: Bearer admin-token" \
  -H "Content-Type: application/json" \
  -d '{"reason":"Reviewed the release evidence."}' \
  http://localhost:4874/admin/releases/<release-id>/approve
```

## Configuration

Copy `.env.example` to `.env` for local development. Important production
settings include:

```dotenv
NODE_ENV=production
AUTH_MODE=hybrid
OIDC_ISSUER_URL=https://issuer.example.com
OIDC_AUDIENCE=veripack
OIDC_JWKS_URL=https://issuer.example.com/.well-known/jwks.json
OIDC_REQUIRE_PACKAGE_SCOPE=true
PUBLIC_REGISTRY_URL=https://registry.example.com
DATABASE_SSL=true
S3_AUTO_CREATE_BUCKET=false
CORS_ORIGINS=https://dashboard.example.com
RATE_LIMIT_BACKEND=postgres
METRICS_TOKEN=<secret>
GITHUB_OIDC_ENABLED=true
GITHUB_ALLOWED_REPOSITORIES=acme/widgets
GITHUB_TOKEN_EXCHANGE_SECRET=<secret>
```

Production refuses to start when authentication, HTTPS, Postgres TLS, S3
provisioning, distributed rate limiting, or metrics access are not configured
correctly. Secrets belong in a secret manager, not in `.env` committed to
GitHub.

The baseline uses a single `GITHUB_PACKAGE_SCOPE`. The V1 contract replaces it
with a per-repository/workflow scope map and rejects a global multi-repo scope.

## Production deployment

The included Compose file is for development. A production topology should use:

- managed PostgreSQL with encrypted point-in-time backups;
- private S3-compatible storage with versioning and retention controls;
- a separate backup bucket/account with versioning, object lock, and an
  inventory manifest covering every referenced object;
- Verdaccio on a private network with no public listener and two rotating
  least-privilege service identities;
- TLS at the gateway ingress;
- an OIDC provider and short-lived tokens, plus admin MFA and step-up
  re-authentication;
- a secret manager for database, S3, Verdaccio, and OIDC credentials;
- separate gateway and audit/replay worker deployments;
- the V1 alert pack, queue-age monitoring, restore drills, and a tested
  `veripack registry rebuild`.

Start the local observability profile after the gateway is running:

```bash
docker compose -f docker-compose.observability.yml up -d
```

Prometheus is available at <http://localhost:9091> and Grafana at
<http://localhost:3001>.

Read [`docs/production-runbook.md`](docs/production-runbook.md) for the
deployment contract, release procedure, backup requirements, and staging exit
criteria.

Process roles:

```bash
PROCESS_ROLE=gateway node apps/gateway/dist/index.js
PROCESS_ROLE=worker  node apps/gateway/dist/index.js
```

Run migrations once per release, before replicas start:

```bash
pnpm --filter @veripack/gateway migrate:dist
```

## Security model

### Trust boundaries

- Package archives are untrusted input.
- Static analysis never executes package code.
- The V1 guarantee covers gateway-mediated publishes and installs only. Direct
  public-npm or direct-tarball bypass is out of scope; a CI/lockfile check
  detects non-gateway resolutions and reports them.
- The LLM receives the structured change set and intent, not tarballs or source
  text by default; selected hunks require a per-org opt-in.
- Verdaccio is not a public trust boundary; only approved releases are replayed,
  and its network isolation and rotating service identities are hard invariants.
- Admin decisions require authentication and are recorded as append-only events.
- Install events are written before a tarball is served and fail closed with
  503 if they cannot be recorded.

### Authentication

Development uses static bearer tokens for convenience. Production uses generic
OIDC JWT validation with:

- issuer and audience validation;
- remote JWKS signature validation;
- role claims for publisher/admin access;
- a deployment-scoped organization claim; V1 is single-tenant and makes no
  tenant-isolation claim;
- package-scope claims for least-privilege publishing.

Publish-capable tokens reject `*`; `*` is allowed only for read-only install
tokens. GitHub publish tokens use protected/exact refs and per-repository/workflow
scopes.

The dashboard uses authorization-code + PKCE for generic OIDC providers and a
state-protected GitHub OAuth flow when `DASHBOARD_AUTH_PROVIDER=github`. GitHub
identities are exchanged server-side for short-lived Veripack tokens. Gateway
sessions are stored in encrypted HttpOnly cookies. The V1 contract adds
server-side `__Host-` sessions, idle/absolute timeouts, rotation, CSRF,
revocation, admin MFA, and step-up re-authentication for high-risk actions.

### Production completion requirements

The baseline application features are implemented. The V1 contract adds the
controls listed under [V1 contract gaps](#v1-contract-gaps); those require code
and schema changes before production. A production owner still has to perform
environment-specific controls that cannot be completed inside a local checkout:

- provision a real OIDC/GitHub application, managed Postgres, private S3,
  Verdaccio, TLS, and secret-manager entries;
- provision the separate backup bucket/account with versioning and object lock,
  and run `pnpm backup:restore-check` with a disposable cloud scratch database;
- verify every object in the backup inventory manifest and run
  `veripack registry rebuild` plus a sample install after restore;
- provision a Docker/Podman runtime for the dedicated worker before enabling
  `SANDBOX_ENABLE_ON_AUDIT` (the default keeps dynamic execution disabled);
- run OIDC-authenticated npm, pnpm, and Bun publish/install tests in staging;
- exercise Verdaccio service-identity rotation, admin MFA/step-up, yanked and
  quarantined download blocking, install-event fail-closed behavior, blocklist
  precedence, and missing-artifact recovery;
- configure alert thresholds, on-call ownership, retention, and deployment
  rollback procedures.

## Verification evidence

The project has been checked with:

```bash
pnpm test          # 53 gateway tests passed
pnpm typecheck     # passed
pnpm build         # gateway and Next.js builds passed
node --check scripts/smoke-test.mjs
node --check scripts/veripack-cli.mjs
pnpm smoke         # publish/audit/approve/install/reject flow passed
```

The latest full smoke run verified:

- first safe release held for review;
- approved safe release installed;
- safe follow-up auto-approved and installed;
- review release held, approved, replayed, and installed;
- risky release rejected and blocked from installation.

These checks cover the baseline, not the full V1 contract. The protocol is shared
by npm, pnpm, and Bun. The included smoke script uses npm for portability; run
the equivalent client commands in staging before a production launch.

## Repository layout

```text
apps/gateway/          Fastify gateway, auth, routes, audit worker, migrations
apps/web/              Next.js dashboard and OIDC session routes
packages/shared/       Shared TypeScript audit/release types
examples/              Safe, review, and risky example packages
verdaccio/             Private Verdaccio configuration
scripts/               Verdaccio bootstrap, smoke test, and preflight CLI
action.yml             Reusable GitHub Action for CI preflight checks
observability/         Prometheus scrape configuration
docker-compose.observability.yml  Local Prometheus/Grafana stack
docs/                  Product specification, ADRs, and production runbook
Dockerfile.gateway     Production gateway image
Dockerfile.web         Production dashboard image
.env.example           Local and production configuration reference
```

## Project status

The V1 contract is implemented (see [V1 contract status](#v1-contract-status)).
It should not be exposed directly to production users until the deployment
owner has configured real identity/data services, TLS, backups, monitoring,
sandbox runtime capacity, and a successful three-client staging run. The
design contract in [`docs/v1-spec.md`](docs/v1-spec.md) is the source of
truth for V1 behavior.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

Copyright 2026 Prateek

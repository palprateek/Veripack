# Production runbook

This runbook describes the minimum deployment contract for Veripack. The
repository now contains production-oriented authentication and transport
guards, but deployment is not complete until these external controls are
configured and exercised in a staging environment.

## Required topology

```text
npm / Bun / pnpm clients
          │ TLS
          ▼
   gateway (public)
      │       │
      │       └── managed Postgres + pg-boss
      │
      ├── private S3 bucket
      └── private Verdaccio service

   dashboard (private, OIDC)
          │ private network
          └──────────────► gateway
```

Only the gateway and the dashboard ingress are public. Postgres, the S3
endpoint, and Verdaccio must not have public listeners. Use a managed database
and object store with backups, encryption, versioning, and access logs.

V1 is single-tenant per deployment. Do not share one deployment across tenants;
`org_id` is a deployment key, not a tenant-isolation boundary. Verdaccio runs on
the private network with two least-privilege service identities (`gateway-a` and
`gateway-b`) so credentials can rotate without a write outage.

## Gateway configuration

Set `NODE_ENV=production`, `AUTH_MODE=oidc` or `AUTH_MODE=hybrid`, and configure:

- `OIDC_ISSUER_URL`, `OIDC_AUDIENCE`, and `OIDC_JWKS_URL`
- `OIDC_ROLE_CLAIM`, `OIDC_ORG_CLAIM`, and `OIDC_PACKAGE_CLAIM`
- `OIDC_ADMIN_ROLES` and `OIDC_PUBLISHER_ROLES`
- `OIDC_REQUIRE_PACKAGE_SCOPE=true` for least-privilege CI publishers
- `ORG_ID` matching the deployment-scoped organization claim in every access
  token; this is a deployment guard, not a tenant-isolation boundary
- `PUBLIC_REGISTRY_URL` using HTTPS
- `TRUST_PROXY=true` only when the gateway is behind a trusted TLS ingress;
  otherwise leave it false to prevent client-spoofed forwarding headers
- `DATABASE_SSL=true` and `DATABASE_SSL_REJECT_UNAUTHORIZED=true`
- `S3_AUTO_CREATE_BUCKET=false`, with the bucket provisioned before startup
- an explicit `CORS_ORIGINS` list containing only the dashboard origins

The gateway accepts OIDC bearer JWTs for both registry and admin requests.
Admin routes require an admin role. Publisher tokens may be restricted with a
package scope such as `@acme/*` or `@acme/payments`. Admins bypass package
scope checks for operational recovery.

For GitHub Actions federation, additionally set `GITHUB_OIDC_ENABLED=true`,
allowlist exact repositories and publisher workflow refs, configure separate
exact admin workflow refs with `GITHUB_ADMIN_WORKFLOW_REFS`, and configure
`GITHUB_TOKEN_EXCHANGE_SECRET`, and have the workflow exchange its GitHub OIDC
token at `/-/auth/github/actions/exchange`. The returned Veripack token is
short-lived and package-scope constrained. For dashboard GitHub OAuth, use
`DASHBOARD_AUTH_PROVIDER=github`, allowlist GitHub users, and configure the
GitHub OAuth client values.

GitHub publish tokens must use protected or exact refs (`ref_protected === true`
or an explicitly configured protected branch). Wildcard publisher refs and
pull-request refs are rejected in production. Package scopes are configured per
repository/workflow, not as one global multi-repo scope. Publish-capable tokens
must use exact names or `@scope/*`; `*` is allowed only for read-only install
tokens.

The following values are development-only and must not be used in production:

- `AUTH_MODE=static`
- `VERIPACK_TOKEN=dev-token`
- `ADMIN_TOKEN=admin-token`
- `S3_ACCESS_KEY_ID=dev` or `S3_SECRET_ACCESS_KEY=dev`
- `S3_AUTO_CREATE_BUCKET=true`

Use a secret manager for database credentials, S3 credentials, Verdaccio
credentials, and OIDC client secrets. Never place them in an image, Compose
file, source tree, or build log.

## Identity and scope matrix

| Identity | Read/install | Publish | Review (`/review/*`) | Admin (`/admin/*`) |
|---|---|---|---|---|
| Read-only token (`READ_TOKEN`, `read: ["*"]`) | yes | no | no | no |
| Publisher (OIDC/GitHub, publish scopes) | within read scopes | within publish scopes, never `*` | no | no |
| Reviewer (OIDC reviewer role, `REVIEWER_TOKEN`, GitHub reviewer repo/user) | yes | no | approve/reject within policy | no |
| Admin | yes | yes | yes | yes |

Scopes are separate per action: `read_scope` and `publish_scope` claims (the
legacy `package_scope` maps to both and is deprecated). `*` is valid only for
read; wildcard publish scopes are rejected in production, including in
`GITHUB_PACKAGE_SCOPES`. GitHub scopes are configured per repository with
`GITHUB_PACKAGE_SCOPES` (`owner/repo` or `owner/repo:workflow_ref` keys); a
single legacy `GITHUB_PACKAGE_SCOPE` is accepted only for one repository.
Publisher workflow tokens must come from a protected ref (`ref_protected` or
`GITHUB_PROTECTED_BRANCHES`); pull-request refs and wildcard workflow refs are
rejected in production.

High-risk admin actions — overrides, quarantine, un-yank, and policy
loosening — require a fresh step-up assertion (`step_up_until` claim, within
15 minutes) in federated modes; static local tokens are exempt. Reviewers
cannot override, quarantine, yank, or change policy; those stay admin-only
in the lifecycle even if a route is reached.

## Process roles and scaling

Run database migrations as a one-shot release step with `pnpm db:migrate` in a
checkout, or `pnpm --filter @veripack/gateway migrate:dist` in the production
image. Then run:

- one or more HTTP instances with `PROCESS_ROLE=gateway`;
- one or more audit and replay workers with `PROCESS_ROLE=worker`;
- `PROCESS_ROLE=all` only for local development or a single-process staging
  deployment.

Set `AUDIT_WORKER_REQUIRED=true` on production gateways; readiness then fails
closed when no worker heartbeat is fresh.

The queue uses Postgres through pg-boss. Configure the retry and retention
values with `AUDIT_JOB_*` variables. Set `RATE_LIMIT_BACKEND=postgres` for
multi-replica deployments; this uses the shared `rate_limit_buckets` table.
The durable audit outbox retries queue dispatch and recovers pending releases
whose queue lease expires. The ingress should still enforce coarse abuse
limits.

Expose `/metrics` only to Prometheus and set `METRICS_TOKEN` in production.
The repository includes `docker-compose.observability.yml` for a local
Prometheus/Grafana profile.

Expose `/livez` for process liveness and `/readyz` for Postgres, an
authenticated Verdaccio check with the active service identity, and a fresh
audit-worker heartbeat. Keep `/health` available to operators but do not expose
database connection details or upstream credentials in monitoring output.

## Database roles and evidence immutability

Migration `007_v1_evidence_model.sql` separates schema ownership from the
runtime role. The application must connect as a non-owner role; a schema owner
bypasses grants, so revoked `UPDATE`/`DELETE` privileges would have no effect.

Provision the role as the migration owner before applying `007`:

```sql
create role veripack_app login password '<from the secret manager>';
grant connect on database veripack to veripack_app;
grant usage on schema public to veripack_app;
grant select, insert, update, delete on all tables in schema public to veripack_app;
grant usage, select on all sequences in schema public to veripack_app;
```

Run migrations with `EVIDENCE_APP_ROLE=veripack_app` and the owner connection.
The migration grants `SELECT`/`INSERT` on `audits`, `approvals`, and
`audit_events`, grants `SELECT`/`INSERT`/`UPDATE` on `release_current_audits`,
and revokes `UPDATE`/`DELETE` on the evidence tables. Then point the gateway and
worker `DATABASE_URL` values at `veripack_app`.

If the role is provisioned after `007` has already been applied, run the grant
and revoke statements manually as the owner:

```sql
grant usage on schema public to veripack_app;
grant select, insert on audits, approvals, audit_events to veripack_app;
grant select, insert, update on release_current_audits to veripack_app;
revoke update, delete on audits, approvals, audit_events from veripack_app;
revoke delete on release_current_audits from veripack_app;
```

Triggers reject every `UPDATE` and `DELETE` on `audits`, `approvals`, and
`audit_events` regardless of role. Migration `007` fails if legacy approvals
contain `reviewer_type = 'agent'`; resolve those rows manually rather than
letting the migration rewrite evidence. Apply new migrations as the owner, then
grant the runtime role the privileges each new migration requires.

## Policy control

Policies use the strict structured model in ADR 0011. Unknown keys or wrong
types in a database policy or in `AUDIT_POLICY_JSON` prevent boot or fail the
request; a semantic change with an unchanged version is rejected.

- Tightening activates immediately with a single admin
  (`POST /admin/policy`, also `PUT`).
- Loosening requires a recorded reason and creates a change request. A second
  admin can approve it immediately (`POST /admin/policy/requests/:id/approve`),
  or the requester can approve after the 24-hour cooling-off. Requests left
  open past seven days expire and must be recreated.
- Preview before saving with `POST /admin/policy` and `dryRun: true`, or check
  affected pending releases with `GET /admin/policy/impact?version=<version>`.
  Impact and dry-run cover pending releases only; activation never changes
  approved releases.
- The safety floor (critical findings block, intent required, no auto-approval
  for binary/obfuscated content or a missing previous artifact) is a code
  constant and cannot be loosened by any policy value.

## Serving boundary

Yanked, quarantined, pending, and rejected releases are never downloadable,
including via lockfile-pinned tarball URLs (404, with a blocked install
event). Every packument and tarball decision writes a synchronous
`install_events` row; if that write fails the gateway returns 503 and serves
no bytes. The blocklist (`/admin/blocklist`) is checked before release state,
the audit cache, and serving, and takes precedence over all three; revoking
an entry restores service. Dist-tags are authoritative in the `dist_tags`
table and mirrored to Verdaccio — a mirror failure keeps the database
authoritative and writes `package.dist_tag_mirror_failed`. `latest` is
computed as the highest stable installable version and is absent when only
prereleases exist. If an approved artifact disappears from object storage,
serving fails closed with 503, the release is held (`artifact.missing`), and
an admin resolves it with `POST /admin/releases/:id/artifact/reupload`
(bytes must match the recorded SHA-256 digest) or by rejecting the release.
Check state with `GET /admin/releases/:id/artifact` and recent decisions with
`GET /admin/install-events`.

## Durable replay

Approvals commit the decision, approval row, audit event, and a `replay_jobs`
row in one transaction; publishing to Verdaccio is asynchronous. A replay
worker claims jobs with `FOR UPDATE SKIP LOCKED` and a lease
(`REPLAY_LEASE_MS`), verifies the tarball SHA-256 against the release digest
before replaying, and retries with backoff (`REPLAY_BACKOFF_MS`) up to
`REPLAY_MAX_ATTEMPTS`. Expired leases are taken over automatically — no
release stays in an in-progress replay. Exhausted jobs land in `failed`,
write `release.replay_failed`, and surface in the
`veripack_replay_jobs_failed` metric. `releases.replay_state` is a
compatibility projection of the job state; the job row is authoritative.
Poll cadence is `REPLAY_POLL_MS`. Replay workers run with
`PROCESS_ROLE=worker` or `all`.

## Dashboard sessions and MFA

Dashboard sessions are server-side (`012_dashboard_sessions.sql`); browsers
hold only an opaque id in the `__Host-veripack_session` cookie (`HttpOnly`,
`Secure` in production, `SameSite=Lax`, `Path=/`, no `Domain`). Sessions idle
out after 30 minutes and expire absolutely after 12 hours; ids rotate on
login and on step-up, and all sessions for a subject can be revoked on role
or password change. State-changing dashboard requests require the session's
CSRF token. Set `DASHBOARD_INTERNAL_SECRET` (at least 32 characters) on both
the gateway and the web tier; it authenticates the internal session API and
derives the encryption key for stored access tokens and TOTP secrets.

Admin MFA is required in production. Enrollment: sign in, open **Security**
(or the `/mfa` page shown at login), enroll an authenticator, verify a code,
and store the one-time recovery codes offline. Recovery: use a recovery code
at the MFA prompt (each code works once), then re-enroll. If all codes are
lost, an operator can reset MFA by deleting the subject's `dashboard_mfa`
row, which forces re-enrollment at next login. High-risk actions (overrides,
policy loosening, quarantine, un-yank, token rotation) require a step-up
verified within 15 minutes; verify from **Security → Step-up verification**.

## Dashboard configuration

Production dashboard access requires:

```text
DASHBOARD_AUTH_MODE=oidc
OIDC_ISSUER_URL=...
OIDC_CLIENT_ID=...
OIDC_CLIENT_SECRET=...
OIDC_REDIRECT_URI=https://dashboard.example.com/api/auth/callback
SESSION_SECRET=<at least 32 random characters>
GATEWAY_URL=http://gateway.internal:4874
```

For GitHub OAuth dashboard login, set `DASHBOARD_AUTH_PROVIDER=github`,
`GITHUB_CLIENT_ID`, and `GITHUB_CLIENT_SECRET` instead of the generic OIDC
provider values, keep the exact callback URL registered in the GitHub OAuth
application, and configure `GITHUB_ADMIN_USERS`/`GITHUB_PUBLISHER_USERS` in the
gateway.

Register only the exact callback URL with the identity provider. The dashboard
uses authorization-code flow with PKCE, validates the ID-token issuer,
audience, nonce, and signature, and stores the gateway access token in an
encrypted, HttpOnly, same-site session cookie. Dashboard action routes reject
cross-origin POSTs.

The V1 contract hardens sessions further: server-side sessions in `__Host-`
cookies (`HttpOnly`, `Secure`, `SameSite=Lax`), a 30-minute idle and 12-hour
absolute timeout, session-ID rotation on login and privilege change, CSRF
protection on every state-changing request, immediate revocation on password or
role change, rate-limited login, and audit events for authentication. High-risk
actions (overrides, policy loosening, quarantine, un-yank, and token rotation)
require step-up re-authentication within 15 minutes. Admin accounts require MFA
in production (TOTP with one-time recovery codes; WebAuthn can be added later);
this is not yet implemented in the baseline.

Policy control is asymmetric: tightening is single-admin and immediate, while
loosening requires a second admin or a 24-hour cooling-off, a visible diff, and
a recorded reason. Policy/engine changes never retroactively change approved
releases; they affect pending decisions only.

## Release procedure

1. Build immutable gateway and dashboard images from a reviewed commit.
2. Generate an SBOM and scan dependencies and images for known vulnerabilities.
3. Provision or verify the private Postgres database, the primary S3 bucket,
   the separate backup bucket/account with versioning and object lock, the
   Verdaccio service and its two service identities, the OIDC application, TLS
   certificate, and ingress policy.
4. Run migrations once with `pnpm --filter @veripack/gateway migrate:dist` (or
   `node dist/migrate-cli.js` inside the gateway image); do not let every
   deployment replica race migrations.
5. Deploy one gateway and one worker in staging.
6. Run the npm, Bun, and pnpm publish/install smoke flows with OIDC tokens.
7. Verify pending, approved, rejected, yanked, and quarantined behavior. A
   yanked release must return 404 even for a lockfile-pinned tarball URL;
   quarantine must block every resolution.
8. Verify that a publisher token cannot access another package scope or any
   admin endpoint, that publish-capable tokens reject `*`, and that read-only
   tokens cannot publish.
9. Verify that allowed and blocked install attempts both produce install events,
   that a missing approved artifact fails closed with 503, and that a blocklist
   entry takes precedence over a cached audit.
10. Promote with a canary gateway and watch queue age, audit failures, replay
    failures, 4xx/5xx rates, latency, and database saturation.

## Verdaccio identity rotation and rebuild

Verdaccio runs with two service identities (`VERDACCIO_IDENTITIES` JSON with
`a`/`b` entries, `VERDACCIO_ACTIVE_IDENTITY` selects the live one). Readiness
authenticates with the active identity, not just `/-/ping`. Rotate every 90
days with `veripack registry identity rotate --identity <a|b>` (admin token,
step-up required): the gateway verifies the new identity before switching,
records `verdaccio.identity_rotated`, and only then should the old identity
be revoked in Verdaccio's htpasswd. Emergency revocation may accept a brief
publish outage. After a restore, run `veripack registry rebuild` to requeue
replays for approved/overridden releases (creation order, digest-verified by
the replay worker), then a sample install; resolve `artifact_missing`
entries with `veripack registry artifact reupload --release <id> --file
<tarball>`. Prometheus alert rules live in
`observability/prometheus/veripack-alerts.yml`.

## Backup and incident controls

- Backups are a consistent pair: a Postgres dump and the S3 objects it
  references. Use a separate backup bucket/account with versioning and object
  lock. Write an inventory manifest containing every referenced key, size, and
  SHA-256.
- Take encrypted, point-in-time Postgres backups and test a restore at least
  monthly.
- Run `RESTORE_DATABASE_URL=... pnpm backup:restore-check` against a disposable
  scratch database. The command uploads the custom-format dump and verifies the
  restored database before reporting success. The operator environment must
  provide `pg_dump` and `pg_restore` from a version-compatible PostgreSQL client.
- Restore verification must check every object in the inventory manifest, not
  only row counts. After a restore, run `veripack registry rebuild` and a sample
  install before declaring recovery complete.
- Enable S3 versioning/object lock or an equivalent immutable retention policy
  for tarballs and evidence.
- Keep Verdaccio storage backed up, or make approved replay from S3 a tested
  recovery operation.
- Rotate OIDC client secrets, S3 credentials, database credentials, and
  Verdaccio credentials on a schedule and after any exposure. Rotate Verdaccio
  on a 90-day interval by switching the active service identity, verifying
  readiness, then revoking the old identity; emergency revocation accepts a
  brief publish outage.
- If a release is unsafe, quarantine it first. If the incident is confirmed,
  terminally reject it with a reason. Yank is the withdrawal path for an
  approved release that is not a suspected compromise; if the release is already
  yanked, it is already blocked, so record the incident and leave it yanked.
  Preserve the append-only event and approval history either way.
- If the queue is unhealthy, stop new promotion only after verifying that
  pending tarballs remain isolated from Verdaccio. Re-queue audits from the
  admin API after recovery.
- If an artifact is missing, hold the release as `artifact_missing`, alert, and
  resolve it with a digest-matching re-upload or a rejection. Do not approve or
  reject automatically.
- Monitor the V1 alert pack: oldest pending release age, outbox unsent
  age, replay `in_progress` age, missing worker heartbeat, audit failure rate,
  upstream audit 5xx rate, readiness failures, and install-block spikes. Each
  alert must link to a runbook action.

## Staging exit criteria

Do not call the service production-ready until a normal Docker or Kubernetes
environment has passed the full smoke test, a backup restore has verified every
inventory object and digest, `veripack registry rebuild` and a sample install
have succeeded, OIDC and package-scope rejection paths have been tested, yanked
and quarantined downloads are blocked, install events fail closed, admin MFA and
step-up are enforced, Verdaccio identity rotation has been exercised, the
CI/lockfile bypass check reports non-gateway resolutions, and the team has
documented on-call ownership and alert thresholds.

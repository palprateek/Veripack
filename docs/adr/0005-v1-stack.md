# V1 stack: TypeScript, Postgres, S3, pg-boss, Next.js

Status: accepted

We will use TypeScript/Node for the registry gateway, audit engine, and CLI; Postgres for metadata and the job queue (`pg-boss`); S3-compatible object storage for tarballs and evidence; Next.js for the dashboard; GitHub OAuth and OIDC for identity; and a pnpm workspace monorepo. Verdaccio remains the npm protocol/proxy/storage layer behind the gateway. Bun is an optional CLI runtime and distribution target, not the server runtime.

## Consequences

- The stack stays compatible with npm tooling (`pacote`, `arborist`, npm registry semantics) instead of fighting it.
- Postgres doubles as the queue for v1; a dedicated queue is a later scaling decision.
- Bun can package the CLI later without changing the server.

import { beforeEach, afterEach, describe, expect, it } from "vitest";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import type { FastifyRequest } from "fastify";
import {
  assertPackageAccess,
  assertStepUp,
  authenticateAdmin,
  authenticatePublisher,
  authenticateReviewer,
  AuthError,
  type AuthUser,
} from "./auth.js";
import {
  issueGithubExchangeToken,
  resolveGithubScopes,
  verifyGithubActionsToken,
  verifyGithubExchangeToken,
  verifyGithubOAuthToken,
} from "./github-auth.js";
import { config as defaultConfig, type Config } from "./config.js";

const request = (authorization: string): FastifyRequest =>
  ({ headers: { authorization } }) as FastifyRequest;

function config(overrides: Partial<Config>): Config {
  return { ...defaultConfig, ...overrides };
}

describe("gateway authentication", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it("supports local static publisher and admin tokens", async () => {
    const local = config({
      AUTH_MODE: "static",
      VERIPACK_TOKEN: "publisher-secret",
      ADMIN_TOKEN: "admin-secret",
      ORG_ID: "org-a",
      DEFAULT_PUBLISHER: "ci-publisher",
      ADMIN_USER: "operator",
    });

    await expect(
      authenticatePublisher(request("Bearer publisher-secret"), local),
    ).resolves.toMatchObject({
      username: "ci-publisher",
      role: "publisher",
      orgId: "org-a",
    });
    await expect(
      authenticateAdmin(request("Bearer admin-secret"), local),
    ).resolves.toMatchObject({ username: "operator", role: "admin" });
    await expect(
      authenticateAdmin(request("Bearer publisher-secret"), local),
    ).rejects.toMatchObject({ statusCode: 401 });
  });

  it("validates OIDC claims and enforces package scopes", async () => {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    const jwksUrl = "https://issuer.example.test/keys-auth-test";
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () =>
      new Response(JSON.stringify({ keys: [{ ...jwk, kid: "auth-test" }] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });

    try {
      const oidc = config({
        AUTH_MODE: "oidc",
        OIDC_ISSUER_URL: "https://issuer.example.test",
        OIDC_AUDIENCE: "veripack",
        OIDC_JWKS_URL: jwksUrl,
        OIDC_ROLE_CLAIM: "roles",
        OIDC_ORG_CLAIM: "org_id",
        OIDC_PACKAGE_CLAIM: "package_scope",
        OIDC_PUBLISHER_ROLES: ["publisher"],
        OIDC_ADMIN_ROLES: ["admin"],
        OIDC_REQUIRE_PACKAGE_SCOPE: true,
        ORG_ID: "org-a",
      });
      const token = await new SignJWT({
        roles: ["publisher"],
        org_id: "org-a",
        package_scope: ["@team/*"],
        preferred_username: "build-bot",
      })
        .setProtectedHeader({ alg: "RS256", kid: "auth-test" })
        .setIssuer(oidc.OIDC_ISSUER_URL)
        .setAudience(oidc.OIDC_AUDIENCE)
        .setSubject("subject-1")
        .setExpirationTime("10m")
        .sign(privateKey);

      const user = await authenticatePublisher(request(`Bearer ${token}`), oidc);
      expect(user).toMatchObject({
        username: "build-bot",
        role: "publisher",
        orgId: "org-a",
        scopes: { read: ["@team/*"], publish: ["@team/*"] },
      });
      expect(() => assertPackageAccess(user, "@team/package", "read")).not.toThrow();
      expect(() => assertPackageAccess(user, "@team/package", "publish")).not.toThrow();
      expect(() => assertPackageAccess(user, "@other/package", "read")).toThrow(AuthError);
      expect(() => assertPackageAccess(user, "@other/package", "publish")).toThrow(AuthError);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("exchanges and validates short-lived GitHub registry tokens", async () => {
    const github = config({
      GITHUB_TOKEN_EXCHANGE_SECRET: "x".repeat(40),
      OIDC_AUDIENCE: "veripack",
      ORG_ID: "org-a",
    });
    const issued = await issueGithubExchangeToken(
      {
        username: "github-actions:acme/app",
        role: "publisher",
        repository: "acme/app",
        scopes: { read: ["@team/*"], publish: ["@team/*"] },
      },
      github,
    );
    expect(issued.accessToken).toMatch(/^veripack-gh\./);
    await expect(verifyGithubExchangeToken(issued.accessToken, github)).resolves.toMatchObject({
      username: "github-actions:acme/app",
      role: "publisher",
      scopes: { read: ["@team/*"], publish: ["@team/*"] },
    });
    await expect(
      verifyGithubExchangeToken(issued.accessToken, { ...github, ORG_ID: "org-b" }),
    ).rejects.toThrow(/organization/i);
  });

  it("validates GitHub Actions issuer, repository, and workflow ref", async () => {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () =>
      new Response(JSON.stringify({ keys: [{ ...jwk, kid: "github-test" }] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    try {
      const github = config({
        GITHUB_OIDC_ENABLED: true,
        GITHUB_OIDC_ISSUER: "https://token.actions.githubusercontent.com",
        GITHUB_OIDC_JWKS_URL: "https://token.actions.githubusercontent.com/.well-known/jwks-test",
        GITHUB_OIDC_AUDIENCE: "veripack",
        GITHUB_ALLOWED_REPOSITORIES: ["acme/app"],
        GITHUB_ALLOWED_WORKFLOW_REFS: ["refs/heads/main"],
        GITHUB_PACKAGE_SCOPE: "@team/*",
      });
      const token = await new SignJWT({
        repository: "acme/app",
        ref: "refs/heads/main",
        job_workflow_ref: "acme/app/.github/workflows/release.yml@refs/heads/main",
      })
        .setProtectedHeader({ alg: "RS256", kid: "github-test" })
        .setIssuer(github.GITHUB_OIDC_ISSUER)
        .setAudience(github.GITHUB_OIDC_AUDIENCE)
        .setSubject("repo:acme/app:ref:refs/heads/main")
        .setExpirationTime("10m")
        .sign(privateKey);
      await expect(verifyGithubActionsToken(token, github)).resolves.toMatchObject({
        username: "github-actions:acme/app",
        scopes: { read: ["@team/*"], publish: ["@team/*"] },
      });

      await expect(
        verifyGithubActionsToken(
          token,
          config({
            ...github,
            GITHUB_ADMIN_REPOSITORIES: ["acme/app"],
            GITHUB_ADMIN_WORKFLOW_REFS: [
              "acme/app/.github/workflows/admin.yml@refs/heads/main",
            ],
          }),
        ),
      ).rejects.toThrow(/administrator access/i);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("maps an allowed GitHub OAuth user to a publisher", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () =>
      new Response(JSON.stringify({ login: "alice" }), { status: 200 });
    try {
      const github = config({
        GITHUB_PUBLISHER_USERS: ["alice"],
        GITHUB_PACKAGE_SCOPE: "@team/*",
      });
      await expect(verifyGithubOAuthToken("oauth-token", github)).resolves.toMatchObject({
        username: "github:alice",
        role: "publisher",
        scopes: { read: ["@team/*"], publish: ["@team/*"] },
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

describe("P4 scopes, reviewer, and step-up", () => {
  function user(overrides: Partial<AuthUser> = {}): AuthUser {
    return {
      username: "someone",
      role: "publisher",
      orgId: "org-a",
      scopes: {},
      ...overrides,
    };
  }

  it("separates read and publish scopes; publish never honors *", () => {
    const readOnly = user({ scopes: { read: ["*"], publish: [] } });
    expect(() => assertPackageAccess(readOnly, "@team/pkg", "read")).not.toThrow();
    expect(() => assertPackageAccess(readOnly, "anything", "read")).not.toThrow();
    expect(() => assertPackageAccess(readOnly, "@team/pkg", "publish")).toThrow(AuthError);

    const wildcardPublish = user({ scopes: { publish: ["*"] } });
    expect(() => assertPackageAccess(wildcardPublish, "@team/pkg", "publish")).toThrow(AuthError);

    const scoped = user({ scopes: { read: ["@team/*"], publish: ["@team/*"] } });
    expect(() => assertPackageAccess(scoped, "@team/pkg", "read")).not.toThrow();
    expect(() => assertPackageAccess(scoped, "@team/pkg", "publish")).not.toThrow();
    expect(() => assertPackageAccess(scoped, "@other/pkg", "publish")).toThrow(AuthError);
  });

  it("authenticates static read-only and reviewer tokens", async () => {
    const local = config({
      AUTH_MODE: "static",
      VERIPACK_TOKEN: "publisher-secret",
      READ_TOKEN: "install-secret",
      REVIEWER_TOKEN: "reviewer-secret",
      ADMIN_TOKEN: "admin-secret",
      ORG_ID: "org-a",
      REVIEWER_USER: "on-call-reviewer",
    });

    const installer = await authenticatePublisher(request("Bearer install-secret"), local);
    expect(installer.scopes).toEqual({ read: ["*"], publish: [] });
    expect(() => assertPackageAccess(installer, "@team/pkg", "publish")).toThrow(AuthError);

    const reviewer = await authenticateReviewer(request("Bearer reviewer-secret"), local);
    expect(reviewer).toMatchObject({ username: "on-call-reviewer", role: "reviewer" });
    await expect(
      authenticatePublisher(request("Bearer reviewer-secret"), local),
    ).rejects.toMatchObject({ statusCode: 401 });
  });

  it("requires a fresh step-up outside static mode", () => {
    const oidc = config({ AUTH_MODE: "oidc" });
    expect(() => assertStepUp(user({ stepUpUntil: null }), oidc)).toThrow(AuthError);
    expect(() =>
      assertStepUp(user({ stepUpUntil: Date.now() - 1_000 }), oidc),
    ).toThrow(/step-up/);
    expect(() =>
      assertStepUp(user({ stepUpUntil: Date.now() + 60_000 }), oidc),
    ).not.toThrow();
    expect(() =>
      assertStepUp(user({ stepUpUntil: null }), config({ AUTH_MODE: "static" })),
    ).not.toThrow();
  });

  it("resolves per-repository GitHub scopes and rejects a global multi-repo scope", () => {
    const mapped = config({
      GITHUB_ALLOWED_REPOSITORIES: ["acme/app", "acme/lib"],
      GITHUB_PACKAGE_SCOPES: JSON.stringify({
        "acme/app": { read: ["@app/*"], publish: ["@app/*"] },
        "acme/lib": { read: ["@lib/*"], publish: ["@lib/*"] },
      }),
    });
    expect(resolveGithubScopes(mapped, "acme/lib")).toEqual({
      read: ["@lib/*"],
      publish: ["@lib/*"],
    });

    const globalLegacy = config({
      GITHUB_ALLOWED_REPOSITORIES: ["acme/app", "acme/lib"],
      GITHUB_PACKAGE_SCOPE: "@team/*",
    });
    expect(() => resolveGithubScopes(globalLegacy, "acme/app")).toThrow(
      /multiple repositories/,
    );
  });

  it("rejects GitHub pull-request refs and requires protected refs in production", async () => {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () =>
      new Response(JSON.stringify({ keys: [{ ...jwk, kid: "github-p4" }] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    try {
      const base = config({
        GITHUB_OIDC_ENABLED: true,
        GITHUB_OIDC_ISSUER: "https://token.actions.githubusercontent.com",
        GITHUB_OIDC_JWKS_URL: "https://token.actions.githubusercontent.com/.well-known/jwks-p4",
        GITHUB_OIDC_AUDIENCE: "veripack",
        GITHUB_ALLOWED_REPOSITORIES: ["acme/app"],
        GITHUB_ALLOWED_WORKFLOW_REFS: ["refs/heads/main", "refs/pull/7/merge"],
        GITHUB_PACKAGE_SCOPE: "@team/*",
      });
      const sign = (claims: Record<string, unknown>) =>
        new SignJWT({
          repository: "acme/app",
          job_workflow_ref: "acme/app/.github/workflows/release.yml@refs/heads/main",
          ...claims,
        })
          .setProtectedHeader({ alg: "RS256", kid: "github-p4" })
          .setIssuer(base.GITHUB_OIDC_ISSUER)
          .setAudience(base.GITHUB_OIDC_AUDIENCE)
          .setSubject("repo:acme/app")
          .setExpirationTime("10m")
          .sign(privateKey);

      await expect(
        verifyGithubActionsToken(await sign({ ref: "refs/pull/7/merge" }), base),
      ).rejects.toThrow(/pull-request/);

      const production = { ...base, NODE_ENV: "production" as const };
      await expect(
        verifyGithubActionsToken(await sign({ ref: "refs/heads/main" }), production),
      ).rejects.toThrow(/protected ref/);
      await expect(
        verifyGithubActionsToken(
          await sign({ ref: "refs/heads/main", ref_protected: true }),
          production,
        ),
      ).resolves.toMatchObject({ role: "publisher" });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

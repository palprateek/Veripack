import { createSecretKey } from "node:crypto";
import {
  createRemoteJWKSet,
  jwtVerify,
  SignJWT,
  type JWTPayload,
} from "jose";
import type { Config } from "./config.js";
import type { AuthRole, PackageScopes } from "./auth.js";

export interface GithubPrincipal {
  username: string;
  role: AuthRole;
  repository?: string;
  scopes: PackageScopes;
  stepUpUntil?: number | null;
}

const ACTIONS_ISSUER = "https://token.actions.githubusercontent.com";
const INTERNAL_ISSUER = "veripack:github";

function secret(config: Config) {
  if (config.GITHUB_TOKEN_EXCHANGE_SECRET.length < 32) {
    throw new Error("GitHub token exchange is not configured with a strong secret.");
  }
  return createSecretKey(Buffer.from(config.GITHUB_TOKEN_EXCHANGE_SECRET, "utf8"));
}

function matches(pattern: string, value: string): boolean {
  if (pattern === "*") return true;
  if (pattern === value) return true;
  if (pattern.endsWith("/*")) return value.startsWith(pattern.slice(0, -1));
  return false;
}

function listClaim(payload: JWTPayload, key: string): string[] {
  const value = payload[key];
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === "string");
  return typeof value === "string" ? value.split(/[\s,]+/).filter(Boolean) : [];
}

interface GithubScopeEntry {
  read?: string[];
  publish?: string[];
}

function stringArray(value: unknown, key: string): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new Error(`GITHUB_PACKAGE_SCOPES entry "${key}" must contain string arrays.`);
  }
  return value as string[];
}

/** Parses the per-repository scope map: { "owner/repo": { read, publish } }. */
export function parseGithubPackageScopes(
  config: Config,
): Map<string, GithubScopeEntry> {
  const raw = config.GITHUB_PACKAGE_SCOPES.trim();
  const entries = new Map<string, GithubScopeEntry>();
  if (!raw) return entries;

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("GITHUB_PACKAGE_SCOPES must be valid JSON.");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("GITHUB_PACKAGE_SCOPES must be a JSON object keyed by repository.");
  }
  for (const [key, value] of Object.entries(parsed)) {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      throw new Error(`GITHUB_PACKAGE_SCOPES entry "${key}" must be an object.`);
    }
    const entry = value as { read?: unknown; publish?: unknown };
    entries.set(key, {
      read: stringArray(entry.read, key),
      publish: stringArray(entry.publish, key),
    });
  }
  return entries;
}

function assertPublishScopes(scopes: string[] | undefined, config: Config): void {
  if (scopes?.includes("*") && config.NODE_ENV === "production") {
    throw new Error("Wildcard publish scopes are not allowed in production.");
  }
}

/**
 * Resolves the scopes for one repository (and optionally one workflow ref).
 * A single legacy GITHUB_PACKAGE_SCOPE is accepted only when it cannot cover
 * more than one repository.
 */
export function resolveGithubScopes(
  config: Config,
  repository: string,
  workflowRef?: string,
): PackageScopes {
  const map = parseGithubPackageScopes(config);
  const entry =
    (workflowRef ? map.get(`${repository}:${workflowRef}`) : undefined) ??
    map.get(repository);
  if (entry) {
    const publish = entry.publish ?? [];
    assertPublishScopes(publish, config);
    return { read: entry.read ?? [], publish };
  }

  const legacy = config.GITHUB_PACKAGE_SCOPE.trim();
  if (legacy) {
    if (config.GITHUB_ALLOWED_REPOSITORIES.length > 1) {
      throw new Error(
        "A single GITHUB_PACKAGE_SCOPE cannot cover multiple repositories. Configure GITHUB_PACKAGE_SCOPES per repository.",
      );
    }
    assertPublishScopes([legacy], config);
    return { read: [legacy], publish: [legacy] };
  }

  throw new Error(
    `No package scope configured for GitHub repository ${repository}. Set GITHUB_PACKAGE_SCOPES.`,
  );
}

function isProtectedRef(payload: JWTPayload, ref: string, config: Config): boolean {
  if (payload["ref_protected"] === true) return true;
  return config.GITHUB_PROTECTED_BRANCHES.some(
    (branch) => branch === ref || `refs/heads/${branch}` === ref,
  );
}

export async function verifyGithubActionsToken(
  token: string,
  config: Config,
): Promise<GithubPrincipal> {
  if (!config.GITHUB_OIDC_ENABLED) {
    throw new Error("GitHub OIDC federation is disabled.");
  }
  const keySet = createRemoteJWKSet(new URL(config.GITHUB_OIDC_JWKS_URL));
  const { payload } = await jwtVerify(token, keySet, {
    issuer: config.GITHUB_OIDC_ISSUER || ACTIONS_ISSUER,
    audience: config.GITHUB_OIDC_AUDIENCE,
  });
  const repository = typeof payload.repository === "string" ? payload.repository : "";
  if (!repository || !config.GITHUB_ALLOWED_REPOSITORIES.some((pattern) => matches(pattern, repository))) {
    throw new Error("GitHub repository is not allowed to publish to this registry.");
  }

  const ref = typeof payload.ref === "string" ? payload.ref : "";
  const workflowRef = typeof payload.job_workflow_ref === "string" ? payload.job_workflow_ref : "";
  if (!ref || !workflowRef) {
    throw new Error("GitHub workflow token is missing ref or job_workflow_ref claims.");
  }
  if (ref.startsWith("refs/pull/")) {
    throw new Error("GitHub pull-request refs cannot publish to this registry.");
  }
  if (
    config.NODE_ENV === "production" &&
    config.GITHUB_ALLOWED_WORKFLOW_REFS.some((pattern) => pattern.includes("*"))
  ) {
    throw new Error("Wildcard GitHub workflow refs are not allowed in production.");
  }
  if (config.NODE_ENV === "production" && !isProtectedRef(payload, ref, config)) {
    throw new Error(
      "GitHub publisher tokens require a protected ref (ref_protected) or a configured protected branch.",
    );
  }
  if (
    config.GITHUB_ALLOWED_WORKFLOW_REFS.length === 0 ||
    !config.GITHUB_ALLOWED_WORKFLOW_REFS.some(
      (pattern) => matches(pattern, ref) || matches(pattern, workflowRef),
    )
  ) {
    throw new Error("GitHub workflow ref is not allowed to publish to this registry.");
  }

  const adminRepository = config.GITHUB_ADMIN_REPOSITORIES.some((pattern) =>
    matches(pattern, repository),
  );
  if (
    adminRepository &&
    (config.GITHUB_ADMIN_WORKFLOW_REFS.length === 0 ||
      !config.GITHUB_ADMIN_WORKFLOW_REFS.some(
        (pattern) => matches(pattern, workflowRef) || matches(pattern, ref),
      ))
  ) {
    throw new Error("GitHub workflow is not allowed to obtain administrator access.");
  }

  const reviewerRepository = config.GITHUB_REVIEWER_REPOSITORIES.some(
    (pattern) => matches(pattern, repository),
  );
  const role: AuthRole = adminRepository
    ? "admin"
    : reviewerRepository
      ? "reviewer"
      : "publisher";

  return {
    username: `github-actions:${repository}`,
    role,
    repository,
    scopes:
      role === "admin"
        ? {}
        : role === "reviewer"
          ? { read: ["*"], publish: [] }
          : resolveGithubScopes(config, repository, workflowRef),
  };
}

export async function verifyGithubOAuthToken(
  token: string,
  config: Config,
): Promise<GithubPrincipal> {
  const response = await fetch(`${config.GITHUB_API_URL.replace(/\/+$/, "")}/user`, {
    headers: {
      authorization: `Bearer ${token}`,
      accept: "application/vnd.github+json",
      "user-agent": "veripack-github-auth",
    },
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) throw new Error("GitHub OAuth token is invalid or expired.");
  const body = (await response.json()) as { login?: unknown };
  const login = typeof body.login === "string" ? body.login : "";
  if (!login) throw new Error("GitHub user response did not contain a login.");

  const isAdmin = config.GITHUB_ADMIN_USERS.includes(login);
  const isReviewer = config.GITHUB_REVIEWER_USERS.includes(login);
  if (!isAdmin && !isReviewer && !config.GITHUB_PUBLISHER_USERS.includes(login)) {
    throw new Error("GitHub user is not allowed to access this registry.");
  }
  const role: AuthRole = isAdmin ? "admin" : isReviewer ? "reviewer" : "publisher";

  if (role === "publisher") {
    const legacy = config.GITHUB_PACKAGE_SCOPE.trim();
    if (!legacy) {
      throw new Error("GitHub publisher tokens require a package scope.");
    }
    assertPublishScopes([legacy], config);
    return {
      username: `github:${login}`,
      role,
      scopes: { read: [legacy], publish: [legacy] },
    };
  }
  return {
    username: `github:${login}`,
    role,
    scopes: role === "admin" ? {} : { read: ["*"], publish: [] },
  };
}

export async function issueGithubExchangeToken(
  principal: GithubPrincipal,
  config: Config,
): Promise<{ accessToken: string; expiresAt: number }> {
  if (principal.role === "publisher" && !principal.scopes.publish?.length) {
    throw new Error("GitHub publisher exchange tokens require a publish scope.");
  }
  const expiresAt = Date.now() + config.GITHUB_TOKEN_TTL_SECONDS * 1_000;
  const token = await new SignJWT({
    roles: [principal.role],
    org_id: config.ORG_ID,
    read_scope: principal.scopes.read,
    publish_scope: principal.scopes.publish,
    provider: "github",
    repository: principal.repository,
    ...(principal.stepUpUntil != null
      ? { step_up_until: Math.floor(principal.stepUpUntil / 1_000) }
      : {}),
  })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuer(INTERNAL_ISSUER)
    .setAudience(config.OIDC_AUDIENCE || "veripack")
    .setSubject(principal.username)
    .setExpirationTime(Math.floor(expiresAt / 1_000))
    .sign(secret(config));
  return { accessToken: `veripack-gh.${token}`, expiresAt };
}

export async function verifyGithubExchangeToken(
  presented: string,
  config: Config,
): Promise<GithubPrincipal> {
  const token = presented.startsWith("veripack-gh.")
    ? presented.slice("veripack-gh.".length)
    : presented;
  const { payload } = await jwtVerify(token, secret(config), {
    issuer: INTERNAL_ISSUER,
    audience: config.OIDC_AUDIENCE || "veripack",
  });
  if (payload.org_id !== config.ORG_ID || payload.provider !== "github") {
    throw new Error("GitHub exchange token is not issued for this organization.");
  }
  const roles = listClaim(payload, "roles");
  const username = typeof payload.sub === "string" ? payload.sub : "";
  const role: AuthRole | null = roles.includes("admin")
    ? "admin"
    : roles.includes("reviewer")
      ? "reviewer"
      : roles.includes("publisher")
        ? "publisher"
        : null;
  if (!username || !role) throw new Error("Invalid GitHub exchange token claims.");

  const readClaim = payload["read_scope"];
  const publishClaim = payload["publish_scope"];
  let scopes: PackageScopes;
  if (readClaim !== undefined || publishClaim !== undefined) {
    scopes = {
      read: listClaim(payload, "read_scope"),
      publish: listClaim(payload, "publish_scope"),
    };
  } else {
    const legacy = listClaim(payload, "package_scope");
    scopes =
      legacy.length > 0 ? { read: legacy, publish: legacy } : {};
  }
  if (role === "publisher" && !scopes.publish?.length) {
    throw new Error("GitHub exchange token has no publish scope.");
  }
  if (role === "reviewer") {
    scopes = { read: scopes.read ?? ["*"], publish: [] };
  }

  const stepUp = payload["step_up_until"];
  return {
    username,
    role,
    repository: typeof payload.repository === "string" ? payload.repository : undefined,
    scopes,
    stepUpUntil:
      typeof stepUp === "number" ? (stepUp > 1e12 ? stepUp : stepUp * 1_000) : null,
  };
}

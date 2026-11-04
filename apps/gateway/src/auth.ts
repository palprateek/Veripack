import { timingSafeEqual } from "node:crypto";
import type { FastifyRequest } from "fastify";
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import type { Config } from "./config.js";
import { verifyGithubExchangeToken } from "./github-auth.js";

export class AuthError extends Error {
  readonly statusCode: 401 | 403;

  constructor(message = "Authentication required.", statusCode: 401 | 403 = 401) {
    super(message);
    this.name = "AuthError";
    this.statusCode = statusCode;
  }
}

export type AuthRole = "publisher" | "reviewer" | "admin";

export interface PackageScopes {
  /** Undefined means unrestricted; an empty list means no access. */
  read?: string[];
  publish?: string[];
}

export interface AuthUser {
  username: string;
  role: AuthRole;
  orgId: string;
  scopes: PackageScopes;
  /** Epoch milliseconds until which step-up authentication is fresh. */
  stepUpUntil?: number | null;
}

type OidcKeySet = ReturnType<typeof createRemoteJWKSet>;

const oidcKeySets = new Map<string, OidcKeySet>();

function safeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

function parseAuthorization(
  request: FastifyRequest,
): { scheme: "bearer" | "basic"; value: string } | null {
  const header = request.headers.authorization;
  if (!header) return null;
  const [scheme, ...rest] = header.split(" ");
  const value = rest.join(" ").trim();
  if (!scheme || !value) return null;

  if (scheme.toLowerCase() === "bearer") {
    return { scheme: "bearer", value };
  }
  if (scheme.toLowerCase() === "basic") {
    return { scheme: "basic", value };
  }
  return null;
}

function basicPassword(encoded: string): string | null {
  try {
    const decoded = Buffer.from(encoded, "base64").toString("utf8");
    const separator = decoded.indexOf(":");
    if (separator === -1) return null;
    return decoded.slice(separator + 1);
  } catch {
    return null;
  }
}

function claim(payload: JWTPayload, path: string): unknown {
  let current: unknown = payload;
  for (const part of path.split(".")) {
    if (typeof current !== "object" || current === null) return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}

function stringList(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.flatMap((item) => stringList(item));
  }
  if (typeof value !== "string") return [];
  return value
    .split(/[\s,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function keySet(config: Config): OidcKeySet {
  const existing = oidcKeySets.get(config.OIDC_JWKS_URL);
  if (existing) return existing;

  const created = createRemoteJWKSet(new URL(config.OIDC_JWKS_URL));
  oidcKeySets.set(config.OIDC_JWKS_URL, created);
  return created;
}

function packageMatches(pattern: string, packageName: string): boolean {
  if (pattern === "*") return true;
  if (pattern === packageName) return true;
  if (pattern.endsWith("/*")) {
    return packageName.startsWith(pattern.slice(0, -1));
  }
  return false;
}

export type PackageAction = "read" | "publish";

export function assertPackageAccess(
  user: AuthUser,
  packageName: string,
  action: PackageAction,
): void {
  if (user.role === "admin") return;
  const patterns = action === "read" ? user.scopes.read : user.scopes.publish;
  if (patterns === undefined) return;
  const allowed = patterns.some((pattern) => {
    // A wildcard is a read-only grant; it never authorizes publishing.
    if (action === "publish" && pattern === "*") return false;
    return packageMatches(pattern, packageName);
  });
  if (!allowed) {
    throw new AuthError(
      `The authenticated identity is not allowed to ${action} ${packageName}.`,
      403,
    );
  }
}

export function assertStepUp(
  user: AuthUser,
  config: Config,
  now: number = Date.now(),
): void {
  // Static tokens are pre-authenticated local credentials; step-up applies to
  // federated and dashboard-asserted sessions.
  if (config.AUTH_MODE === "static") return;
  if (user.stepUpUntil == null || user.stepUpUntil <= now) {
    throw new AuthError(
      "This action requires a fresh step-up authentication.",
      403,
    );
  }
}

let legacyScopeWarned = false;

function warnLegacyPackageScope(): void {
  if (legacyScopeWarned) return;
  legacyScopeWarned = true;
  console.warn(
    "The package_scope claim is deprecated; configure read_scope and publish_scope instead.",
  );
}

function parseStepUpUntil(payload: JWTPayload): number | null {
  const value = payload["step_up_until"];
  if (typeof value === "number" && Number.isFinite(value)) {
    return value > 1e12 ? value : value * 1_000;
  }
  if (typeof value === "string") {
    const parsed = Date.parse(value);
    return Number.isNaN(parsed) ? null : parsed;
  }
  return null;
}

function roleSatisfies(actual: AuthRole, required: AuthRole): boolean {
  if (actual === "admin") return true;
  return actual === required;
}

function requiredRoleMessage(required: AuthRole): string {
  return required === "admin"
    ? "Administrator role required."
    : required === "reviewer"
      ? "Reviewer role required."
      : "Publisher role required.";
}

async function authenticateOidc(
  token: string,
  requiredRole: AuthRole,
  config: Config,
): Promise<AuthUser> {
  let verified: JWTPayload;
  try {
    ({ payload: verified } = await jwtVerify(token, keySet(config), {
      issuer: config.OIDC_ISSUER_URL,
      audience: config.OIDC_AUDIENCE,
      clockTolerance: config.OIDC_CLOCK_TOLERANCE_SECONDS,
    }));
  } catch {
    throw new AuthError("Invalid OIDC access token.");
  }

  const roles = stringList(claim(verified, config.OIDC_ROLE_CLAIM));
  const isAdmin = config.OIDC_ADMIN_ROLES.some((role) => roles.includes(role));
  const isReviewer = config.OIDC_REVIEWER_ROLES.some((role) =>
    roles.includes(role),
  );
  const isPublisher = config.OIDC_PUBLISHER_ROLES.some((role) =>
    roles.includes(role),
  );

  const role: AuthRole | null = isAdmin
    ? "admin"
    : isReviewer
      ? "reviewer"
      : isPublisher
        ? "publisher"
        : null;
  if (!role || !roleSatisfies(role, requiredRole)) {
    throw new AuthError(requiredRoleMessage(requiredRole), 403);
  }

  const username =
    (typeof verified.preferred_username === "string" &&
      verified.preferred_username) ||
    (typeof verified.email === "string" && verified.email) ||
    verified.sub;
  if (!username) throw new AuthError("OIDC token has no subject.");

  const orgId = claim(verified, config.OIDC_ORG_CLAIM);
  if (typeof orgId !== "string" || orgId !== config.ORG_ID) {
    throw new AuthError("OIDC token is not issued for this organization.", 403);
  }

  const readClaim = claim(verified, config.OIDC_READ_SCOPE_CLAIM);
  const publishClaim = claim(verified, config.OIDC_PUBLISH_SCOPE_CLAIM);
  const legacy = stringList(claim(verified, config.OIDC_PACKAGE_CLAIM));
  let read: string[] | undefined;
  let publish: string[] | undefined;
  let scoped = false;
  if (readClaim !== undefined || publishClaim !== undefined) {
    read = stringList(readClaim);
    publish = stringList(publishClaim);
    scoped = true;
  } else if (legacy.length > 0) {
    warnLegacyPackageScope();
    read = legacy;
    publish = legacy;
    scoped = true;
  }

  if (
    config.NODE_ENV === "production" &&
    publish?.includes("*")
  ) {
    throw new AuthError(
      "Wildcard publish scopes are not allowed in production.",
      403,
    );
  }

  if (
    requiredRole === "publisher" &&
    role === "publisher" &&
    config.OIDC_REQUIRE_PACKAGE_SCOPE &&
    (publish === undefined || publish.length === 0)
  ) {
    throw new AuthError("OIDC token has no package scope.", 403);
  }

  return {
    username,
    role,
    orgId: config.ORG_ID,
    scopes: {
      read: scoped ? read : undefined,
      publish: role === "reviewer" ? [] : scoped ? publish : undefined,
    },
    stepUpUntil: parseStepUpUntil(verified),
  };
}

async function authenticate(
  request: FastifyRequest,
  config: Config,
  requiredRole: AuthRole,
): Promise<AuthUser> {
  const authorization = parseAuthorization(request);
  if (!authorization) {
    throw new AuthError(
      requiredRole === "admin"
        ? "Admin API requires a bearer token."
        : "Registry access requires a bearer token.",
    );
  }

  if (config.AUTH_MODE === "github") {
    if (authorization.scheme !== "bearer") {
      throw new AuthError("GitHub authentication requires a bearer token.");
    }
    try {
      const github = await verifyGithubExchangeToken(authorization.value, config);
      if (!roleSatisfies(github.role, requiredRole)) {
        throw new AuthError(requiredRoleMessage(requiredRole), 403);
      }
      return {
        username: github.username,
        role: github.role,
        orgId: config.ORG_ID,
        scopes: github.scopes,
        stepUpUntil: github.stepUpUntil ?? null,
      };
    } catch (error) {
      if (error instanceof AuthError) throw error;
      throw new AuthError("Invalid GitHub exchange token.");
    }
  }

  if (
    (config.AUTH_MODE === "oidc" || config.AUTH_MODE === "hybrid") &&
    authorization.scheme === "bearer" &&
    authorization.value.startsWith("veripack-gh.")
  ) {
    try {
      const github = await verifyGithubExchangeToken(authorization.value, config);
      if (!roleSatisfies(github.role, requiredRole)) {
        throw new AuthError(requiredRoleMessage(requiredRole), 403);
      }
      return {
        username: github.username,
        role: github.role,
        orgId: config.ORG_ID,
        scopes: github.scopes,
        stepUpUntil: github.stepUpUntil ?? null,
      };
    } catch (error) {
      if (error instanceof AuthError && error.statusCode === 403) throw error;
      // A hybrid deployment accepts either a GitHub exchange token or the
      // configured generic OIDC token. Continue to the OIDC verifier here.
    }
  }

  if (config.AUTH_MODE === "oidc" || config.AUTH_MODE === "hybrid") {
    if (authorization.scheme !== "bearer") {
      throw new AuthError("OIDC authentication requires a bearer JWT.");
    }
    return authenticateOidc(authorization.value, requiredRole, config);
  }

  const presented =
    authorization.scheme === "bearer"
      ? authorization.value
      : basicPassword(authorization.value);
  if (!presented) {
    throw new AuthError("Invalid registry token.");
  }

  if (requiredRole === "admin") {
    if (!safeEqual(presented, config.ADMIN_TOKEN)) {
      throw new AuthError("Invalid admin token.");
    }
    return {
      username: config.ADMIN_USER,
      role: "admin",
      orgId: config.ORG_ID,
      scopes: {},
      stepUpUntil: null,
    };
  }

  if (requiredRole === "reviewer") {
    if (config.REVIEWER_TOKEN && safeEqual(presented, config.REVIEWER_TOKEN)) {
      return {
        username: config.REVIEWER_USER,
        role: "reviewer",
        orgId: config.ORG_ID,
        scopes: { publish: [] },
        stepUpUntil: null,
      };
    }
    if (safeEqual(presented, config.ADMIN_TOKEN)) {
      return {
        username: config.ADMIN_USER,
        role: "admin",
        orgId: config.ORG_ID,
        scopes: {},
        stepUpUntil: null,
      };
    }
    throw new AuthError("Invalid reviewer token.");
  }

  if (config.READ_TOKEN && safeEqual(presented, config.READ_TOKEN)) {
    return {
      username: "read-only-installer",
      role: "publisher",
      orgId: config.ORG_ID,
      scopes: { read: ["*"], publish: [] },
      stepUpUntil: null,
    };
  }
  if (!safeEqual(presented, config.VERIPACK_TOKEN)) {
    throw new AuthError("Invalid registry token.");
  }
  return {
    username: config.DEFAULT_PUBLISHER,
    role: "publisher",
    orgId: config.ORG_ID,
    scopes: {},
    stepUpUntil: null,
  };
}

export function authenticatePublisher(
  request: FastifyRequest,
  config: Config,
): Promise<AuthUser> {
  return authenticate(request, config, "publisher");
}

export function authenticateReviewer(
  request: FastifyRequest,
  config: Config,
): Promise<AuthUser> {
  return authenticate(request, config, "reviewer");
}

export function authenticateAdmin(
  request: FastifyRequest,
  config: Config,
): Promise<AuthUser> {
  return authenticate(request, config, "admin");
}

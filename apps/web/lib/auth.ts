import { createHash, randomBytes } from "node:crypto";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { NextResponse } from "next/server";
import {
  createRemoteJWKSet,
  EncryptJWT,
  jwtDecrypt,
  jwtVerify,
} from "jose";

const SESSION_COOKIE = "__Host-veripack_session";
const CSRF_COOKIE = "veripack_csrf";
const PENDING_COOKIE = "veripack_pending_login";
const STATE_COOKIE = "veripack_oidc_state";
const NONCE_COOKIE = "veripack_oidc_nonce";
const VERIFIER_COOKIE = "veripack_oidc_verifier";
const TRANSIENT_COOKIE_MAX_AGE = 600;

export interface DashboardSession {
  accessToken: string;
  subject: string;
  displayName?: string;
  expiresAt: number;
  sessionId?: string;
  csrfToken?: string;
  role?: string;
  stepUpUntil?: number | null;
}

interface PendingLogin {
  accessToken: string;
  subject: string;
  displayName?: string;
  role: string;
}

interface OidcDiscovery {
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri?: string;
  end_session_endpoint?: string;
}

interface WebAuthConfig {
  mode: "static" | "oidc";
  provider: "generic" | "github";
  gatewayUrl: string;
  staticToken: string;
  issuerUrl: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scopes: string;
  jwksUrl: string;
  githubAuthorizeUrl: string;
  githubTokenUrl: string;
  githubClientId: string;
  githubClientSecret: string;
  sessionSecret: string;
  internalSecret: string;
  production: boolean;
}

function required(name: string, value: string | undefined): string {
  if (!value?.trim()) throw new Error(`${name} must be configured.`);
  return value.trim();
}

function authConfig(): WebAuthConfig {
  const mode = process.env.DASHBOARD_AUTH_MODE === "oidc" ? "oidc" : "static";
  const provider = process.env.DASHBOARD_AUTH_PROVIDER === "github" ? "github" : "generic";
  const production = process.env.NODE_ENV === "production";
  const config: WebAuthConfig = {
    mode,
    provider,
    gatewayUrl: process.env.GATEWAY_URL ?? "http://localhost:4874",
    staticToken:
      process.env.DASHBOARD_ACCESS_TOKEN ??
      process.env.ADMIN_TOKEN ??
      "admin-token",
    issuerUrl: process.env.OIDC_ISSUER_URL?.trim() ?? "",
    clientId: process.env.OIDC_CLIENT_ID?.trim() ?? "",
    clientSecret: process.env.OIDC_CLIENT_SECRET?.trim() ?? "",
    redirectUri: process.env.OIDC_REDIRECT_URI?.trim() ?? "",
    scopes: process.env.OIDC_SCOPES?.trim() || "openid profile email",
    jwksUrl: process.env.OIDC_JWKS_URL?.trim() ?? "",
    githubAuthorizeUrl:
      process.env.GITHUB_AUTHORIZE_URL?.trim() || "https://github.com/login/oauth/authorize",
    githubTokenUrl:
      process.env.GITHUB_TOKEN_URL?.trim() || "https://github.com/login/oauth/access_token",
    githubClientId: process.env.GITHUB_CLIENT_ID?.trim() || process.env.OIDC_CLIENT_ID?.trim() || "",
    githubClientSecret: process.env.GITHUB_CLIENT_SECRET?.trim() ?? "",
    sessionSecret: process.env.SESSION_SECRET?.trim() ?? "",
    internalSecret:
      process.env.DASHBOARD_INTERNAL_SECRET?.trim() ||
      process.env.SESSION_SECRET?.trim() ||
      "",
    production,
  };

  const isBuild = process.env.NEXT_PHASE === "phase-production-build";
  if (production && config.mode !== "oidc" && !isBuild) {
    throw new Error(
      "DASHBOARD_AUTH_MODE=oidc is required when the dashboard runs in production.",
    );
  }
  if (config.mode === "oidc") {
    required("OIDC_REDIRECT_URI", config.redirectUri);
    required("SESSION_SECRET", config.sessionSecret);
    if (config.sessionSecret.length < 32) {
      throw new Error("SESSION_SECRET must contain at least 32 characters.");
    }
    if (config.provider === "generic") {
      required("OIDC_CLIENT_ID", config.clientId);
      required("OIDC_ISSUER_URL", config.issuerUrl);
      if (production) required("OIDC_CLIENT_SECRET", config.clientSecret);
    } else {
      required("GITHUB_CLIENT_ID", config.githubClientId);
      if (production) required("GITHUB_CLIENT_SECRET", config.githubClientSecret);
    }
  }

  return config;
}

function sessionKey(secret: string): Uint8Array {
  return createHash("sha256").update(secret).digest();
}

function base64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function secureCookie(config: WebAuthConfig) {
  return {
    httpOnly: true,
    secure: config.production,
    sameSite: "lax" as const,
    path: "/",
  };
}

async function gatewayInternal(
  config: WebAuthConfig,
  path: string,
  init: RequestInit,
): Promise<Response> {
  return fetch(`${config.gatewayUrl}${path}`, {
    ...init,
    headers: {
      "content-type": "application/json",
      "x-veripack-dashboard-key": config.internalSecret,
      ...(init.headers ?? {}),
    },
    cache: "no-store",
  });
}

interface GatewaySessionBody {
  sessionId: string;
  csrfToken: string;
  idleExpiresAt: string;
  absoluteExpiresAt: string;
}

async function createGatewaySession(
  config: WebAuthConfig,
  pending: PendingLogin & { mfaVerified?: boolean },
): Promise<GatewaySessionBody | { error: string; status: number }> {
  const response = await gatewayInternal(config, "/-/dashboard/sessions", {
    method: "POST",
    body: JSON.stringify(pending),
  });
  const body = (await response.json().catch(() => ({}))) as Partial<
    GatewaySessionBody
  > & { error?: string };
  if (!response.ok || !body.sessionId || !body.csrfToken) {
    return {
      error: body.error ?? "Gateway session creation failed.",
      status: response.status || 502,
    };
  }
  return body as GatewaySessionBody;
}

function applySessionCookies(
  response: NextResponse,
  config: WebAuthConfig,
  created: GatewaySessionBody,
): void {
  const maxAge = Math.max(
    Math.floor((Date.parse(created.absoluteExpiresAt) - Date.now()) / 1_000),
    60,
  );
  response.cookies.set(SESSION_COOKIE, created.sessionId, {
    ...secureCookie(config),
    httpOnly: true,
    maxAge,
  });
  response.cookies.set(CSRF_COOKIE, created.csrfToken, {
    ...secureCookie(config),
    httpOnly: true,
    maxAge,
  });
}

async function whoamiRole(
  config: WebAuthConfig,
  accessToken: string,
): Promise<string> {
  try {
    const response = await fetch(`${config.gatewayUrl}/-/whoami`, {
      headers: { authorization: `Bearer ${accessToken}` },
      cache: "no-store",
    });
    if (!response.ok) return "publisher";
    const body = (await response.json()) as { role?: unknown };
    return typeof body.role === "string" ? body.role : "publisher";
  } catch {
    return "publisher";
  }
}

export async function getMfaStatus(
  subject: string,
): Promise<{ enrolled: boolean; enabled: boolean }> {
  const config = authConfig();
  try {
    const response = await gatewayInternal(
      config,
      `/-/dashboard/mfa/status?subject=${encodeURIComponent(subject)}`,
      { method: "GET" },
    );
    if (!response.ok) return { enrolled: false, enabled: false };
    const body = (await response.json()) as {
      enrolled?: boolean;
      enabled?: boolean;
    };
    return { enrolled: Boolean(body.enrolled), enabled: Boolean(body.enabled) };
  } catch {
    return { enrolled: false, enabled: false };
  }
}

export async function getPendingLogin(): Promise<PendingLogin | null> {
  const config = authConfig();
  const value = (await cookies()).get(PENDING_COOKIE)?.value;
  if (!value) return null;
  try {
    const { payload } = await jwtDecrypt<PendingLogin>(
      value,
      sessionKey(config.sessionSecret),
    );
    if (typeof payload.accessToken !== "string" || typeof payload.subject !== "string") {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

async function encodePending(
  pending: PendingLogin,
  config: WebAuthConfig,
): Promise<string> {
  return new EncryptJWT(pending as unknown as Record<string, unknown>)
    .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
    .setIssuedAt()
    .setExpirationTime("10m")
    .encrypt(sessionKey(config.sessionSecret));
}

/**
 * Completes a login after any required MFA gate: creates the server-side
 * session and sets the `__Host-` cookie. Redirects to /mfa when an admin
 * must enroll or verify first.
 */
export async function completeLogin(
  request: Request,
  pending: PendingLogin,
): Promise<NextResponse> {
  const config = authConfig();

  if (pending.role === "admin") {
    const status = await getMfaStatus(pending.subject);
    if (status.enabled) {
      const created = await createGatewaySession(config, {
        ...pending,
        mfaVerified: false,
      });
      if ("error" in created) {
        const response = NextResponse.redirect(new URL("/mfa", request.url));
        response.cookies.set(PENDING_COOKIE, await encodePending(pending, config), {
          ...secureCookie(config),
          maxAge: TRANSIENT_COOKIE_MAX_AGE,
        });
        return response;
      }
      const response = NextResponse.redirect(new URL("/", request.url));
      applySessionCookies(response, config, created);
      return response;
    }
    if (config.production) {
      const response = NextResponse.redirect(new URL("/mfa", request.url));
      response.cookies.set(PENDING_COOKIE, await encodePending(pending, config), {
        ...secureCookie(config),
        maxAge: TRANSIENT_COOKIE_MAX_AGE,
      });
      return response;
    }
  }

  const created = await createGatewaySession(config, pending);
  if ("error" in created) {
    return NextResponse.json(
      { error: created.error },
      { status: created.status },
    );
  }
  const response = NextResponse.redirect(new URL("/", request.url));
  applySessionCookies(response, config, created);
  response.cookies.delete(PENDING_COOKIE);
  return response;
}

export async function getDashboardSession(): Promise<DashboardSession | null> {
  const config = authConfig();
  if (config.mode === "static") {
    return {
      accessToken: config.staticToken,
      subject: "static-admin",
      displayName: "Local administrator",
      expiresAt: Date.now() + 86_400_000,
    };
  }

  const cookieStore = await cookies();
  const sessionId = cookieStore.get(SESSION_COOKIE)?.value;
  if (!sessionId) return null;

  try {
    const response = await gatewayInternal(
      config,
      "/-/dashboard/sessions/validate",
      { method: "POST", body: JSON.stringify({ sessionId }) },
    );
    if (!response.ok) return null;
    const body = (await response.json()) as {
      subject: string;
      displayName?: string | null;
      role?: string;
      accessToken: string;
      stepUpUntil?: number | null;
      absoluteExpiresAt: string;
    };
    return {
      accessToken: body.accessToken,
      subject: body.subject,
      displayName: body.displayName ?? undefined,
      expiresAt: Date.parse(body.absoluteExpiresAt),
      sessionId,
      csrfToken: cookieStore.get(CSRF_COOKIE)?.value,
      role: body.role,
      stepUpUntil: body.stepUpUntil ?? null,
    };
  } catch {
    return null;
  }
}

/** Validates the CSRF token bound to the caller's session. */
export async function assertDashboardCsrf(request: Request): Promise<void> {
  const config = authConfig();
  if (config.mode === "static") {
    assertSameOrigin(request);
    return;
  }
  assertSameOrigin(request);
  const cookieStore = await cookies();
  const sessionId = cookieStore.get(SESSION_COOKIE)?.value;
  const csrfToken = cookieStore.get(CSRF_COOKIE)?.value;
  if (!sessionId || !csrfToken) {
    throw new Error("Dashboard CSRF token is missing.");
  }
  const response = await gatewayInternal(
    config,
    "/-/dashboard/sessions/validate",
    {
      method: "POST",
      body: JSON.stringify({ sessionId, csrfToken }),
    },
  );
  const body = (await response.json().catch(() => ({}))) as {
    csrfValid?: boolean;
  };
  if (!response.ok || body.csrfValid !== true) {
    throw new Error("Dashboard CSRF validation failed.");
  }
}

export async function rotateDashboardSessionCookies(
  response: NextResponse,
  created: { sessionId: string; csrfToken: string },
): Promise<void> {
  const config = authConfig();
  response.cookies.set(SESSION_COOKIE, created.sessionId, {
    ...secureCookie(config),
    maxAge: 12 * 60 * 60,
  });
  response.cookies.set(CSRF_COOKIE, created.csrfToken, {
    ...secureCookie(config),
    maxAge: 12 * 60 * 60,
  });
}

export async function callGatewayInternal(
  path: string,
  init: RequestInit,
): Promise<Response> {
  return gatewayInternal(authConfig(), path, init);
}

export function dashboardCookieNames() {
  return { session: SESSION_COOKIE, csrf: CSRF_COOKIE, pending: PENDING_COOKIE };
}

export async function requireDashboardSession(): Promise<DashboardSession> {
  const session = await getDashboardSession();
  if (!session) redirect("/api/auth/login");
  return session;
}

async function discovery(config: WebAuthConfig): Promise<OidcDiscovery> {
  const response = await fetch(
    `${config.issuerUrl.replace(/\/+$/, "")}/.well-known/openid-configuration`,
    { cache: "no-store" },
  );
  if (!response.ok) {
    throw new Error(`OIDC discovery failed with status ${response.status}.`);
  }
  const value = (await response.json()) as Partial<OidcDiscovery>;
  if (!value.authorization_endpoint || !value.token_endpoint) {
    throw new Error("OIDC discovery response is missing required endpoints.");
  }
  return value as OidcDiscovery;
}

export async function startLogin(request: Request): Promise<NextResponse> {
  const config = authConfig();
  if (config.mode === "static") {
    return NextResponse.redirect(new URL("/", request.url));
  }

  const state = base64Url(randomBytes(32));
  const nonce = base64Url(randomBytes(32));
  const verifier = base64Url(randomBytes(48));
  const challenge = base64Url(createHash("sha256").update(verifier).digest());
  const url = config.provider === "github"
    ? new URL(config.githubAuthorizeUrl)
    : new URL((await discovery(config)).authorization_endpoint);
  url.searchParams.set("client_id", config.provider === "github" ? config.githubClientId : config.clientId);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("redirect_uri", config.redirectUri);
  url.searchParams.set("scope", config.provider === "github" ? "read:user user:email" : config.scopes);
  url.searchParams.set("state", state);
  if (config.provider === "generic") {
    url.searchParams.set("nonce", nonce);
    url.searchParams.set("code_challenge", challenge);
    url.searchParams.set("code_challenge_method", "S256");
  }

  const response = NextResponse.redirect(url);
  const cookieOptions = {
    ...secureCookie(config),
    maxAge: TRANSIENT_COOKIE_MAX_AGE,
  };
  response.cookies.set(STATE_COOKIE, state, cookieOptions);
  response.cookies.set(NONCE_COOKIE, nonce, cookieOptions);
  response.cookies.set(VERIFIER_COOKIE, verifier, cookieOptions);
  return response;
}

export async function finishLogin(request: Request): Promise<NextResponse> {
  const config = authConfig();
  if (config.mode === "static") {
    return NextResponse.redirect(new URL("/", request.url));
  }

  const url = new URL(request.url);
  const error = url.searchParams.get("error");
  if (error) {
    return NextResponse.json(
      { error: `OIDC login was denied: ${error}.` },
      { status: 401 },
    );
  }

  const cookieStore = await cookies();
  const state = url.searchParams.get("state");
  const expectedState = cookieStore.get(STATE_COOKIE)?.value;
  const verifier = cookieStore.get(VERIFIER_COOKIE)?.value;
  const expectedNonce = cookieStore.get(NONCE_COOKIE)?.value;
  if (!state || !expectedState || state !== expectedState || !verifier) {
    return NextResponse.json({ error: "Invalid OIDC login state." }, { status: 400 });
  }

  const code = url.searchParams.get("code");
  if (!code) {
    return NextResponse.json({ error: "OIDC callback did not contain a code." }, { status: 400 });
  }

  if (config.provider === "github") {
    const tokenResponse = await fetch(config.githubTokenUrl, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        client_id: config.githubClientId,
        client_secret: config.githubClientSecret,
        code,
        redirect_uri: config.redirectUri,
      }),
      cache: "no-store",
    });
    const tokenBody = (await tokenResponse.json().catch(() => ({}))) as {
      access_token?: unknown;
      error_description?: unknown;
    };
    if (!tokenResponse.ok || typeof tokenBody.access_token !== "string") {
      return NextResponse.json(
        { error: typeof tokenBody.error_description === "string" ? tokenBody.error_description : "GitHub OAuth exchange failed." },
        { status: 502 },
      );
    }
    const gatewayResponse = await fetch(`${config.gatewayUrl}/-/auth/github/oauth/exchange`, {
      method: "POST",
      headers: { authorization: `Bearer ${tokenBody.access_token}`, accept: "application/json" },
      cache: "no-store",
    });
    const gatewayBody = (await gatewayResponse.json().catch(() => ({}))) as {
      accessToken?: unknown;
      expiresAt?: unknown;
      subject?: unknown;
      error?: unknown;
    };
    if (!gatewayResponse.ok || typeof gatewayBody.accessToken !== "string") {
      return NextResponse.json(
        { error: typeof gatewayBody.error === "string" ? gatewayBody.error : "Gateway rejected the GitHub identity." },
        { status: gatewayResponse.status || 502 },
      );
    }
    const subject =
      typeof gatewayBody.subject === "string" ? gatewayBody.subject : "github-user";
    const role = await whoamiRole(config, gatewayBody.accessToken);
    const response = await completeLogin(request, {
      accessToken: gatewayBody.accessToken,
      subject,
      displayName: subject.replace(/^github:/, ""),
      role,
    });
    response.cookies.delete(STATE_COOKIE);
    response.cookies.delete(NONCE_COOKIE);
    response.cookies.delete(VERIFIER_COOKIE);
    return response;
  }

  const provider = await discovery(config);
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    code_verifier: verifier,
  });
  if (config.clientSecret) body.set("client_secret", config.clientSecret);
  const tokenResponse = await fetch(provider.token_endpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
    cache: "no-store",
  });
  const tokenBody = (await tokenResponse.json().catch(() => ({}))) as {
    access_token?: unknown;
    id_token?: unknown;
    expires_in?: unknown;
    error_description?: unknown;
  };
  if (!tokenResponse.ok || typeof tokenBody.access_token !== "string") {
    return NextResponse.json(
      {
        error:
          typeof tokenBody.error_description === "string"
            ? tokenBody.error_description
            : "OIDC token exchange failed.",
      },
      { status: 502 },
    );
  }
  if (config.production && typeof tokenBody.id_token !== "string") {
    return NextResponse.json(
      { error: "OIDC token response did not contain an ID token." },
      { status: 502 },
    );
  }

  let subject = "oidc-user";
  let displayName: string | undefined;
  if (typeof tokenBody.id_token === "string") {
    const jwksUrl = config.jwksUrl || provider.jwks_uri;
    if (!jwksUrl) return NextResponse.json({ error: "OIDC JWKS is not configured." }, { status: 500 });
    try {
      const { payload } = await jwtVerify(
        tokenBody.id_token,
        createRemoteJWKSet(new URL(jwksUrl)),
        { issuer: config.issuerUrl, audience: config.clientId },
      );
      if (expectedNonce && payload.nonce !== expectedNonce) {
        return NextResponse.json({ error: "OIDC nonce validation failed." }, { status: 400 });
      }
      if (typeof payload.sub === "string") subject = payload.sub;
      displayName =
        typeof payload.name === "string"
          ? payload.name
          : typeof payload.preferred_username === "string"
            ? payload.preferred_username
            : typeof payload.email === "string"
              ? payload.email
              : undefined;
    } catch {
      return NextResponse.json({ error: "OIDC identity token validation failed." }, { status: 401 });
    }
  }

  const role = await whoamiRole(config, tokenBody.access_token);
  const response = await completeLogin(request, {
    accessToken: tokenBody.access_token,
    subject,
    displayName,
    role,
  });
  response.cookies.delete(STATE_COOKIE);
  response.cookies.delete(NONCE_COOKIE);
  response.cookies.delete(VERIFIER_COOKIE);
  return response;
}

export async function logout(request: Request): Promise<NextResponse> {
  const config = authConfig();
  const sessionId = (await cookies()).get(SESSION_COOKIE)?.value;
  if (sessionId && config.mode !== "static") {
    await gatewayInternal(config, "/-/dashboard/sessions/revoke", {
      method: "POST",
      body: JSON.stringify({ sessionId }),
    }).catch(() => undefined);
  }
  const response = NextResponse.redirect(new URL("/", request.url));
  response.cookies.delete(SESSION_COOKIE);
  response.cookies.delete(CSRF_COOKIE);
  response.cookies.delete(PENDING_COOKIE);
  response.cookies.delete(STATE_COOKIE);
  response.cookies.delete(NONCE_COOKIE);
  response.cookies.delete(VERIFIER_COOKIE);
  return response;
}

export function assertSameOrigin(request: Request): void {
  const origin = request.headers.get("origin");
  if (!origin || origin !== new URL(request.url).origin) {
    throw new Error("Cross-origin dashboard requests are not allowed.");
  }
}

export const dashboardSessionCookieName = SESSION_COOKIE;

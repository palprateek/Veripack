import type { Config } from "./config.js";
import { encodePackageName } from "./npm/names.js";
import type { NpmPublishPayload, NpmVersionManifest } from "./npm/payload.js";

interface VerdaccioUserResponse {
  ok?: boolean;
  token?: string;
  error?: string;
}

export interface VerdaccioIdentity {
  user: string;
  password: string;
}

/** Parses VERDACCIO_IDENTITIES: {"a": {"user": "...", "password": "..."}}. */
export function parseVerdaccioIdentities(
  config: Config,
): Map<string, VerdaccioIdentity> {
  const identities = new Map<string, VerdaccioIdentity>();
  const raw = config.VERDACCIO_IDENTITIES.trim();
  if (!raw) return identities;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("VERDACCIO_IDENTITIES must be valid JSON.");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("VERDACCIO_IDENTITIES must be a JSON object.");
  }
  for (const [id, value] of Object.entries(parsed)) {
    const entry = value as { user?: unknown; password?: unknown };
    if (typeof entry.user !== "string" || typeof entry.password !== "string") {
      throw new Error(`VERDACCIO_IDENTITIES entry "${id}" needs user and password.`);
    }
    identities.set(id, { user: entry.user, password: entry.password });
  }
  return identities;
}

export class VerdaccioClient {
  private token: string | null = null;
  private readonly identities: Map<string, VerdaccioIdentity>;
  private activeIdentityId: string;

  constructor(private readonly config: Config) {
    this.identities = parseVerdaccioIdentities(config);
    this.activeIdentityId = config.VERDACCIO_ACTIVE_IDENTITY || "a";
  }

  /** The identity currently used for Verdaccio writes. */
  get activeIdentity(): string {
    return this.identities.has(this.activeIdentityId)
      ? this.activeIdentityId
      : "legacy";
  }

  configuredIdentities(): string[] {
    return [...this.identities.keys()];
  }

  private identity(id?: string): { id: string } & VerdaccioIdentity {
    const wanted = id ?? this.activeIdentityId;
    const configured = this.identities.get(wanted);
    if (configured) return { id: wanted, ...configured };
    if (id) throw new Error(`Verdaccio identity "${id}" is not configured.`);
    return {
      id: "legacy",
      user: this.config.VERDACCIO_USER,
      password: this.config.VERDACCIO_PASSWORD,
    };
  }

  private get baseUrl(): string {
    return this.config.VERDACCIO_URL.replace(/\/+$/, "");
  }

  private async loginWith(identity: VerdaccioIdentity): Promise<string> {
    const url = `${this.baseUrl}/-/user/org.couchdb.user:${encodeURIComponent(
      identity.user,
    )}`;

    const response = await fetch(url, {
      method: "PUT",
      headers: {
        "content-type": "application/json",
        accept: "application/json",
        authorization: `Basic ${Buffer.from(
          `${identity.user}:${identity.password}`,
        ).toString("base64")}`,
        "user-agent": "veripack-gateway/0.1",
      },
      body: JSON.stringify({
        _id: `org.couchdb.user:${identity.user}`,
        name: identity.user,
        password: identity.password,
        type: "user",
        roles: [],
        date: new Date().toISOString(),
      }),
      signal: AbortSignal.timeout(15_000),
    });

    const text = await response.text();
    let body: VerdaccioUserResponse = {};
    try {
      body = JSON.parse(text) as VerdaccioUserResponse;
    } catch {
      // Fall through to the error below.
    }

    if (!response.ok || !body.token) {
      throw new Error(
        `Verdaccio login failed (${response.status}): ${body.error ?? text.slice(0, 300)}`,
      );
    }
    return body.token;
  }

  private async login(): Promise<string> {
    this.token = await this.loginWith(this.identity());
    return this.token;
  }

  /** Verifies an identity can authenticate, without switching to it. */
  async verifyIdentity(id?: string): Promise<boolean> {
    try {
      const identity = this.identity(id);
      const token = await this.loginWith(identity);
      const response = await fetch(`${this.baseUrl}/-/whoami`, {
        headers: {
          authorization: `Bearer ${token}`,
          accept: "application/json",
          "user-agent": "veripack-gateway/0.1",
        },
        signal: AbortSignal.timeout(10_000),
      });
      return response.ok;
    } catch {
      return false;
    }
  }

  /**
   * Switches the active identity after verifying the new one authenticates.
   * The previous identity stays configured so it can be revoked in Verdaccio
   * (htpasswd) once the switch is proven.
   */
  async rotateIdentity(id: string): Promise<{ previous: string; active: string }> {
    const previous = this.activeIdentity;
    if (!(await this.verifyIdentity(id))) {
      throw new Error(
        `Verdaccio identity "${id}" could not be verified; keeping "${previous}".`,
      );
    }
    this.activeIdentityId = id;
    this.token = null;
    return { previous, active: this.activeIdentity };
  }

  private async getToken(): Promise<string> {
    return this.token ?? (await this.login());
  }

  private async putPackage(
    packageName: string,
    body: string,
    token: string,
  ): Promise<Response> {
    return fetch(`${this.baseUrl}/${encodePackageName(packageName)}`, {
      method: "PUT",
      headers: {
        "content-type": "application/json",
        accept: "application/json",
        authorization: `Bearer ${token}`,
        "user-agent": "veripack-gateway/0.1",
        "npm-command": "publish",
      },
      body,
      signal: AbortSignal.timeout(60_000),
    });
  }

  private async getVersion(
    packageName: string,
    version: string,
  ): Promise<NpmVersionManifest | null> {
    const response = await fetch(
      `${this.baseUrl}/${encodePackageName(packageName)}`,
      {
        headers: { accept: "application/json" },
        signal: AbortSignal.timeout(15_000),
      },
    );

    if (response.status === 404) return null;
    if (!response.ok) {
      throw new Error(
        `Verdaccio read failed while checking ${packageName}@${version}: ${response.status}`,
      );
    }

    const packument = (await response.json()) as {
      versions?: Record<string, NpmVersionManifest>;
    };
    return packument.versions?.[version] ?? null;
  }

  private async distTagRequest(
    packageName: string,
    tag: string,
    method: "PUT" | "DELETE",
    version?: string,
  ): Promise<void> {
    const url = `${this.baseUrl}/${encodePackageName(packageName)}/-/dist-tags/${encodeURIComponent(tag)}`;
    const body = method === "PUT" ? JSON.stringify(version) : undefined;
    let response = await fetch(url, {
      method,
      headers: {
        accept: "application/json",
        ...(body ? { "content-type": "application/json" } : {}),
        authorization: `Bearer ${await this.getToken()}`,
        "user-agent": "veripack-gateway/0.1",
      },
      body,
      signal: AbortSignal.timeout(30_000),
    });

    if (response.status === 401 || response.status === 403) {
      this.token = null;
      response = await fetch(url, {
        method,
        headers: {
          accept: "application/json",
          ...(body ? { "content-type": "application/json" } : {}),
          authorization: `Bearer ${await this.getToken()}`,
          "user-agent": "veripack-gateway/0.1",
        },
        body,
        signal: AbortSignal.timeout(30_000),
      });
    }

    if (response.ok) return;
    const text = await response.text();
    throw new Error(
      `Verdaccio dist-tag ${method.toLowerCase()} failed (${response.status}): ${text.slice(0, 500)}`,
    );
  }

  async setDistTag(packageName: string, tag: string, version: string): Promise<void> {
    await this.distTagRequest(packageName, tag, "PUT", version);
  }

  async deleteDistTag(packageName: string, tag: string): Promise<void> {
    await this.distTagRequest(packageName, tag, "DELETE");
  }

  async replay(payload: NpmPublishPayload): Promise<void> {
    if (!payload.name || !payload.versions) {
      throw new Error("Cannot replay a publish payload without a name and versions.");
    }

    const version = Object.keys(payload.versions)[0];
    if (!version) {
      throw new Error("Cannot replay a publish payload without a version.");
    }

    const body = JSON.stringify(payload);
    let response = await this.putPackage(payload.name, body, await this.getToken());

    if (response.status === 401 || response.status === 403) {
      // The Verdaccio token may have expired or Verdaccio may have restarted.
      this.token = null;
      response = await this.putPackage(payload.name, body, await this.getToken());
    }

    if (response.ok) return;

    const text = await response.text();
    if (response.status === 409 || response.status === 403) {
      const existing = await this.getVersion(payload.name, version);
      if (existing) {
        const expected = payload.versions[version]?.dist?.integrity;
        const actual = existing.dist?.integrity;
        if (!expected || expected === actual) {
          return;
        }
        throw new Error(
          `Verdaccio already has ${payload.name}@${version} with different content.`,
        );
      }
    }

    throw new Error(
      `Verdaccio publish replay failed (${response.status}): ${text.slice(0, 500)}`,
    );
  }

  async isReachable(): Promise<boolean> {
    try {
      const response = await fetch(`${this.baseUrl}/-/ping`, {
        signal: AbortSignal.timeout(5_000),
      });
      return response.ok;
    } catch {
      return false;
    }
  }

  /** Authenticated readiness: the active identity must actually log in. */
  async isAuthenticated(): Promise<boolean> {
    return this.verifyIdentity();
  }
}

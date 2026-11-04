import { afterEach, describe, expect, it } from "vitest";
import { config as defaultConfig, type Config } from "./config.js";
import { VerdaccioClient } from "./verdaccio.js";

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

function testConfig(overrides: Partial<Config> = {}): Config {
  return {
    ...defaultConfig,
    VERDACCIO_URL: "http://verdaccio.test:4873",
    VERDACCIO_IDENTITIES: JSON.stringify({
      a: { user: "gateway-a", password: "password-a-0123456789" },
      b: { user: "gateway-b", password: "password-b-0123456789" },
    }),
    VERDACCIO_ACTIVE_IDENTITY: "a",
    ...overrides,
  };
}

function stubVerdaccio(validPasswords: Set<string>) {
  globalThis.fetch = (async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.includes("/-/user/")) {
      const authorization = (init?.headers as Record<string, string>)
        ?.authorization;
      const decoded = Buffer.from(
        authorization?.replace("Basic ", "") ?? "",
        "base64",
      ).toString("utf8");
      const password = decoded.split(":").slice(1).join(":");
      if (!validPasswords.has(password)) {
        return new Response(JSON.stringify({ error: "unauthorized" }), {
          status: 401,
        });
      }
      return new Response(JSON.stringify({ token: "tok" }), { status: 200 });
    }
    if (url.includes("/-/whoami")) {
      return new Response(JSON.stringify({ user: {} }), { status: 200 });
    }
    return new Response("{}", { status: 200 });
  }) as typeof fetch;
}

describe("verdaccio dual identity", () => {
  it("uses the configured active identity and rotates after verification", async () => {
    stubVerdaccio(
      new Set(["password-a-0123456789", "password-b-0123456789"]),
    );
    const client = new VerdaccioClient(testConfig());
    expect(client.activeIdentity).toBe("a");
    expect(client.configuredIdentities()).toEqual(["a", "b"]);
    await expect(client.isAuthenticated()).resolves.toBe(true);

    const rotated = await client.rotateIdentity("b");
    expect(rotated).toEqual({ previous: "a", active: "b" });
    expect(client.activeIdentity).toBe("b");
  });

  it("keeps the old identity when the new one cannot authenticate", async () => {
    stubVerdaccio(new Set(["password-a-0123456789"]));
    const client = new VerdaccioClient(testConfig());
    await expect(client.rotateIdentity("b")).rejects.toThrow(/keeping "a"/);
    expect(client.activeIdentity).toBe("a");
  });

  it("fails authenticated readiness with wrong credentials", async () => {
    stubVerdaccio(new Set(["someone-elses-password"]));
    const client = new VerdaccioClient(testConfig());
    await expect(client.isAuthenticated()).resolves.toBe(false);
  });
});

import { afterEach, describe, expect, it } from "vitest";
import { buildServer } from "./server.js";
import { config as defaultConfig, type Config } from "./config.js";

function testContext() {
  const config: Config = {
    ...defaultConfig,
    LOG_LEVEL: "silent",
    AUTH_MODE: "static",
    VERIPACK_TOKEN: "publisher-secret",
    ADMIN_TOKEN: "admin-secret",
  };
  return {
    config,
    pool: { query: async () => ({ rows: [] }) },
    storage: {},
    verdaccio: { isReachable: async () => true },
    boss: { send: async () => "job-id" },
    lifecycle: {
      applyDecision: async () => ({
        outcome: "refused",
        code: "not_found",
        message: "Release not found.",
      }),
      replay: async () => ({
        outcome: "refused",
        code: "not_found",
        message: "Release not found.",
      }),
    },
  } as never;
}

describe("gateway security boundary", () => {
  let app: Awaited<ReturnType<typeof buildServer>> | null = null;

  afterEach(async () => {
    await app?.close();
    app = null;
  });

  it("keeps liveness public but protects registry and admin routes", async () => {
    app = await buildServer(testContext());

    const live = await app.inject({ method: "GET", url: "/livez" });
    expect(live.statusCode).toBe(200);
    expect(live.json()).toEqual({ ok: true });

    const registry = await app.inject({ method: "GET", url: "/@team/package" });
    expect(registry.statusCode).toBe(401);

    const admin = await app.inject({ method: "GET", url: "/admin/releases" });
    expect(admin.statusCode).toBe(401);
  });

  it("accepts publisher identity for whoami but not admin APIs", async () => {
    app = await buildServer(testContext());

    const whoami = await app.inject({
      method: "GET",
      url: "/-/whoami",
      headers: { authorization: "Bearer publisher-secret" },
    });
    expect(whoami.statusCode).toBe(200);
    expect(whoami.json()).toMatchObject({ role: "publisher" });

    const admin = await app.inject({
      method: "GET",
      url: "/admin/releases",
      headers: { authorization: "Bearer publisher-secret" },
    });
    expect(admin.statusCode).toBe(401);
  });

  it("exposes authenticated-compatible Prometheus metrics", async () => {
    app = await buildServer(testContext());
    const metrics = await app.inject({ method: "GET", url: "/metrics" });
    expect(metrics.statusCode).toBe(200);
    expect(metrics.headers["content-type"]).toContain("text/plain");
    expect(metrics.body).toContain("veripack_gateway_requests_total");
  });
});

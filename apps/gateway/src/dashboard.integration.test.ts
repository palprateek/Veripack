import { afterEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { config as defaultConfig, type Config } from "./config.js";
import {
  challengeMfa,
  createDashboardSession,
  csrfMatches,
  enrollMfa,
  getDashboardSession,
  isLoginRateLimited,
  recordAuthEvent,
  revokeDashboardSession,
  rotateDashboardSession,
  totpCode,
  verifyMfaEnrollment,
} from "./dashboard.js";
import { buildServer } from "./server.js";
import { createTestDatabase } from "./test-support/integration-db.js";

const SECRET = "dashboard-internal-secret-for-tests-0123456789";

describe("dashboard sessions (integration)", () => {
  it("creates, validates, rotates, and revokes sessions with CSRF", async () => {
    const db = await createTestDatabase();
    try {
      const created = await createDashboardSession(db.pool, SECRET, {
        subject: "admin-1",
        displayName: "Admin One",
        role: "admin",
        accessToken: "gateway-token",
        mfaLevel: "none",
      });

      const lookup = await getDashboardSession(db.pool, SECRET, created.sessionId, {
        touch: true,
      });
      if (!lookup.valid) throw new Error("Expected a valid session.");
      expect(lookup.session.subject).toBe("admin-1");
      expect(lookup.accessToken).toBe("gateway-token");
      expect(csrfMatches(lookup.session, created.csrfToken)).toBe(true);
      expect(csrfMatches(lookup.session, "wrong-token")).toBe(false);

      const rotated = await rotateDashboardSession(db.pool, SECRET, created.sessionId);
      expect(rotated).not.toBeNull();
      const oldLookup = await getDashboardSession(db.pool, SECRET, created.sessionId);
      expect(oldLookup.valid).toBe(false);

      await revokeDashboardSession(db.pool, rotated!.sessionId, "logout");
      const revoked = await getDashboardSession(db.pool, SECRET, rotated!.sessionId);
      expect(revoked).toMatchObject({ valid: false, reason: "revoked" });
    } finally {
      await db.close();
    }
  });

  it("expires idle and absolute sessions", async () => {
    const db = await createTestDatabase();
    try {
      const t0 = new Date("2026-01-01T00:00:00.000Z");
      const created = await createDashboardSession(db.pool, SECRET, {
        subject: "admin-1",
        role: "admin",
        accessToken: "gateway-token",
        mfaLevel: "none",
        now: t0,
      });

      const idle = await getDashboardSession(db.pool, SECRET, created.sessionId, {
        now: new Date(t0.getTime() + 31 * 60_000),
      });
      expect(idle).toMatchObject({ valid: false, reason: "expired" });

      const absolute = await getDashboardSession(db.pool, SECRET, created.sessionId, {
        now: new Date(t0.getTime() + 13 * 3_600_000),
      });
      expect(absolute).toMatchObject({ valid: false, reason: "expired" });
    } finally {
      await db.close();
    }
  });

  it("rate-limits repeated login failures", async () => {
    const db = await createTestDatabase();
    try {
      for (let i = 0; i < 10; i += 1) {
        await recordAuthEvent(db.pool, {
          subject: "admin-1",
          action: "login",
          success: false,
        });
      }
      expect(await isLoginRateLimited(db.pool, "admin-1")).toBe(true);
      expect(await isLoginRateLimited(db.pool, "admin-2")).toBe(false);
    } finally {
      await db.close();
    }
  });

  it("enrolls MFA, verifies TOTP, and consumes recovery codes once", async () => {
    const db = await createTestDatabase();
    try {
      const { secretBase32 } = await enrollMfa(db.pool, SECRET, "admin-1");
      const { code } = totpCode(secretBase32);
      const recoveryCodes = await verifyMfaEnrollment(
        db.pool,
        SECRET,
        "admin-1",
        code,
      );
      expect(recoveryCodes).toHaveLength(8);

      const later = totpCode(secretBase32, new Date(Date.now() + 30_000));
      await expect(
        challengeMfa(db.pool, SECRET, "admin-1", { code: later.code }),
      ).resolves.toBe(true);
      // The enrollment code cannot be replayed in the same step.
      await expect(
        challengeMfa(db.pool, SECRET, "admin-1", { code }),
      ).resolves.toBe(false);

      const recovery = recoveryCodes![0]!;
      await expect(
        challengeMfa(db.pool, SECRET, "admin-1", { recoveryCode: recovery }),
      ).resolves.toBe(true);
      await expect(
        challengeMfa(db.pool, SECRET, "admin-1", { recoveryCode: recovery }),
      ).resolves.toBe(false);
    } finally {
      await db.close();
    }
  });
});

describe("dashboard session routes (integration)", () => {
  const apps: FastifyInstance[] = [];
  afterEach(async () => {
    await Promise.all(apps.splice(0).map((app) => app.close()));
  });

  function testConfig(overrides: Partial<Config> = {}): Config {
    return {
      ...defaultConfig,
      LOG_LEVEL: "silent",
      NODE_ENV: "production",
      DASHBOARD_INTERNAL_SECRET: SECRET,
      ORG_ID: "org-1",
      RATE_LIMIT_BACKEND: "memory",
      ...overrides,
    };
  }

  it("requires admin MFA enrollment in production before creating a session", async () => {
    const db = await createTestDatabase();
    try {
      const app = await buildServer({
        config: testConfig(),
        pool: db.pool,
        storage: {},
        verdaccio: { isReachable: async () => true },
        boss: {},
        lifecycle: {},
      } as never);
      apps.push(app);
      const headers = { "x-veripack-dashboard-key": SECRET };

      const denied = await app.inject({
        method: "POST",
        url: "/-/dashboard/sessions",
        headers,
        payload: {
          subject: "admin-1",
          role: "admin",
          accessToken: "gateway-token",
        },
      });
      expect(denied.statusCode).toBe(403);
      expect(denied.json().code).toBe("mfa_enrollment_required");

      const unauthorized = await app.inject({
        method: "POST",
        url: "/-/dashboard/sessions",
        headers: { "x-veripack-dashboard-key": "wrong" },
        payload: { subject: "admin-1", role: "admin", accessToken: "t" },
      });
      expect(unauthorized.statusCode).toBe(401);

      const publisher = await app.inject({
        method: "POST",
        url: "/-/dashboard/sessions",
        headers,
        payload: {
          subject: "publisher-1",
          role: "publisher",
          accessToken: "gateway-token",
        },
      });
      expect(publisher.statusCode).toBe(201);
      expect(publisher.json().sessionId).toBeTypeOf("string");
    } finally {
      await db.close();
    }
  });
});

import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import {
  assertSameOrigin,
  callGatewayInternal,
  dashboardCookieNames,
  getPendingLogin,
  rotateDashboardSessionCookies,
} from "@/lib/auth";

async function gatewayJson(
  response: Response,
): Promise<Record<string, unknown>> {
  return (await response.json().catch(() => ({}))) as Record<string, unknown>;
}

/**
 * MFA enrollment, verification, challenge, and step-up. Enrollment and
 * challenge run against the pending login; step-up runs against the live
 * session and rotates its id.
 */
export async function POST(request: Request) {
  try {
    assertSameOrigin(request);
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Forbidden." },
      { status: 403 },
    );
  }

  const body = (await request.json().catch(() => ({}))) as {
    action?: string;
    code?: string;
    recoveryCode?: string;
  };

  if (body.action === "step-up") {
    const cookieStore = await cookies();
    const sessionId = cookieStore.get(dashboardCookieNames().session)?.value;
    if (!sessionId) {
      return NextResponse.json(
        { error: "Dashboard authentication is required." },
        { status: 401 },
      );
    }
    const response = await callGatewayInternal("/-/dashboard/sessions/step-up", {
      method: "POST",
      body: JSON.stringify({
        sessionId,
        code: body.code,
        recoveryCode: body.recoveryCode,
      }),
    });
    const payload = await gatewayJson(response);
    if (!response.ok) {
      return NextResponse.json(payload, { status: response.status });
    }
    const result = NextResponse.json({ ok: true, stepUpUntil: payload.stepUpUntil });
    if (
      typeof payload.sessionId === "string" &&
      typeof payload.csrfToken === "string"
    ) {
      await rotateDashboardSessionCookies(result, {
        sessionId: payload.sessionId,
        csrfToken: payload.csrfToken,
      });
    }
    return result;
  }

  const pending = await getPendingLogin();
  if (!pending) {
    return NextResponse.json(
      { error: "No pending login. Sign in again." },
      { status: 401 },
    );
  }

  if (body.action === "enroll") {
    const response = await callGatewayInternal("/-/dashboard/mfa/enroll", {
      method: "POST",
      body: JSON.stringify({ subject: pending.subject }),
    });
    const payload = await gatewayJson(response);
    return NextResponse.json(payload, { status: response.status });
  }

  if (body.action === "verify" || body.action === "challenge") {
    const path =
      body.action === "verify"
        ? "/-/dashboard/mfa/verify"
        : "/-/dashboard/mfa/challenge";
    const response = await callGatewayInternal(path, {
      method: "POST",
      body: JSON.stringify({
        subject: pending.subject,
        code: body.code,
        recoveryCode: body.recoveryCode,
      }),
    });
    const payload = await gatewayJson(response);
    if (!response.ok) {
      return NextResponse.json(payload, { status: response.status });
    }

    // MFA satisfied: create the real session and clear the pending login.
    const created = await callGatewayInternal("/-/dashboard/sessions", {
      method: "POST",
      body: JSON.stringify({ ...pending, mfaVerified: true }),
    });
    const createdBody = await gatewayJson(created);
    if (!created.ok || typeof createdBody.sessionId !== "string") {
      return NextResponse.json(createdBody, { status: created.status || 502 });
    }
    const result = NextResponse.json({
      ok: true,
      recoveryCodes: payload.recoveryCodes ?? undefined,
    });
    await rotateDashboardSessionCookies(result, {
      sessionId: createdBody.sessionId,
      csrfToken: String(createdBody.csrfToken),
    });
    result.cookies.delete(dashboardCookieNames().pending);
    return result;
  }

  return NextResponse.json({ error: "Unknown MFA action." }, { status: 400 });
}

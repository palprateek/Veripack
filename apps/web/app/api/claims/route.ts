import { NextResponse } from "next/server";
import {
  assertDashboardCsrf,
  getDashboardSession,
} from "@/lib/auth";

const GATEWAY_URL = process.env.GATEWAY_URL ?? "http://localhost:4874";

export async function POST(request: Request) {
  try {
    await assertDashboardCsrf(request);
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Forbidden." },
      { status: 403 },
    );
  }
  const session = await getDashboardSession();
  if (!session) {
    return NextResponse.json(
      { error: "Dashboard authentication is required." },
      { status: 401 },
    );
  }
  const body = await request.text();
  const parsed = JSON.parse(body || "{}") as {
    claimId?: string;
    decision?: string;
    packageName?: string;
    reason?: string;
  };

  const isDecision = parsed.claimId && parsed.decision;
  const path = isDecision
    ? `/admin/claims/${encodeURIComponent(parsed.claimId!)}/${parsed.decision === "approve" ? "approve" : "reject"}`
    : "/claims";
  const response = await fetch(`${GATEWAY_URL}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${session.accessToken}`,
      accept: "application/json",
    },
    body: isDecision ? "{}" : body,
    cache: "no-store",
  });
  const payload = await response.json().catch(() => ({
    error: "The gateway returned a non-JSON response.",
  }));
  return NextResponse.json(payload, { status: response.status });
}

import { NextResponse } from "next/server";
import { assertDashboardCsrf, getDashboardSession } from "@/lib/auth";

const GATEWAY_URL = process.env.GATEWAY_URL ?? "http://localhost:4874";

export async function PUT(request: Request) {
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
    return NextResponse.json({ error: "Dashboard authentication is required." }, { status: 401 });
  }

  const body = await request.json().catch(() => ({}));
  try {
    const response = await fetch(`${GATEWAY_URL}/admin/policy`, {
      method: "PUT",
      headers: {
        authorization: `Bearer ${session.accessToken}`,
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify(body),
      cache: "no-store",
    });
    const payload = await response.json().catch(() => ({ error: "Gateway returned a non-JSON response." }));
    return NextResponse.json(payload, { status: response.status });
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? `Cannot reach the gateway: ${error.message}` : "Cannot reach the gateway." },
      { status: 502 },
    );
  }
}

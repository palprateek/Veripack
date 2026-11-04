import { NextResponse } from "next/server";
import {
  assertDashboardCsrf,
  getDashboardSession,
} from "@/lib/auth";

const GATEWAY_URL = process.env.GATEWAY_URL ?? "http://localhost:4874";

export async function POST(
  request: Request,
  context: { params: Promise<{ id: string }> },
) {
  const { id } = await context.params;
  const body = (await request.json().catch(() => ({}))) as {
    action?: string;
    reason?: string;
  };
  if (body.action !== "approve" && body.action !== "reject") {
    return NextResponse.json({ error: "Unknown review action." }, { status: 400 });
  }

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

  const response = await fetch(
    `${GATEWAY_URL}/review/releases/${encodeURIComponent(id)}/${body.action}`,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${session.accessToken}`,
        accept: "application/json",
      },
      body: JSON.stringify({ reason: body.reason ?? null }),
      cache: "no-store",
    },
  );
  const payload = await response.json().catch(() => ({
    error: "The gateway returned a non-JSON response.",
  }));
  return NextResponse.json(payload, { status: response.status });
}

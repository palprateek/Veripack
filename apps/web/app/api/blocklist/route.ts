import { NextResponse } from "next/server";
import {
  assertDashboardCsrf,
  getDashboardSession,
} from "@/lib/auth";

const GATEWAY_URL = process.env.GATEWAY_URL ?? "http://localhost:4874";

async function proxy(request: Request, method: string, suffix: string) {
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
  const body = method === "GET" ? undefined : await request.text();
  const response = await fetch(`${GATEWAY_URL}/admin/blocklist${suffix}`, {
    method,
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${session.accessToken}`,
      accept: "application/json",
    },
    body: body || undefined,
    cache: "no-store",
  });
  const payload = await response.json().catch(() => ({
    error: "The gateway returned a non-JSON response.",
  }));
  return NextResponse.json(payload, { status: response.status });
}

export async function POST(request: Request) {
  return proxy(request, "POST", "");
}

export async function DELETE(request: Request) {
  const body = (await request
    .clone()
    .json()
    .catch(() => ({}))) as { entryId?: string };
  if (!body.entryId) {
    return NextResponse.json(
      { error: "entryId is required." },
      { status: 400 },
    );
  }
  return proxy(request, "DELETE", `/${encodeURIComponent(body.entryId)}`);
}

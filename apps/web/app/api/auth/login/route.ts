import { startLogin } from "@/lib/auth";

export async function GET(request: Request) {
  try {
    return await startLogin(request);
  } catch (error) {
    return Response.json(
      {
        error: error instanceof Error ? error.message : "OIDC login failed.",
      },
      { status: 500 },
    );
  }
}

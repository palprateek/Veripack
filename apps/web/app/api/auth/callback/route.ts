import { finishLogin } from "@/lib/auth";

export async function GET(request: Request) {
  try {
    return await finishLogin(request);
  } catch (error) {
    return Response.json(
      {
        error: error instanceof Error ? error.message : "OIDC callback failed.",
      },
      { status: 500 },
    );
  }
}

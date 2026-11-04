import { logout } from "@/lib/auth";

export async function POST(request: Request) {
  return logout(request);
}

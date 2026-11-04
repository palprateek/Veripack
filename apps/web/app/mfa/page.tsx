import { MfaForm } from "@/components/MfaForm";
import { getPendingLogin } from "@/lib/auth";
import { redirect } from "next/navigation";

export const dynamic = "force-dynamic";

export default async function MfaPage() {
  const pending = await getPendingLogin();
  if (!pending) redirect("/api/auth/login");

  return (
    <>
      <h1>Multi-factor authentication</h1>
      <p className="muted">
        Administrator sign-in requires MFA. Enroll an authenticator or verify a
        code to continue as {pending.subject}.
      </p>
      <MfaForm mode="login" />
    </>
  );
}

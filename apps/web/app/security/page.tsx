import { MfaForm } from "@/components/MfaForm";
import { getMfaStatus, requireDashboardSession } from "@/lib/auth";
import { formatDate } from "@/lib/format";

export const dynamic = "force-dynamic";

export default async function SecurityPage() {
  const session = await requireDashboardSession();
  const mfa = await getMfaStatus(session.subject);

  return (
    <>
      <h1>Session and MFA</h1>
      <p className="muted">
        Signed in as {session.displayName ?? session.subject}
        {session.role ? ` (${session.role})` : ""}. Sessions idle out after
        30 minutes and expire absolutely after 12 hours.
      </p>
      <p className="muted">
        Step-up:{" "}
        {session.stepUpUntil && session.stepUpUntil > Date.now()
          ? `fresh until ${formatDate(new Date(session.stepUpUntil).toISOString())}`
          : "not verified"}
        . MFA: {mfa.enabled ? "enabled" : mfa.enrolled ? "enrolled, not enabled" : "not enrolled"}.
      </p>
      <h2>Step-up verification</h2>
      <p className="muted">
        High-risk actions (overrides, quarantine, un-yank, policy loosening)
        require a step-up verified within 15 minutes.
      </p>
      <MfaForm mode="step-up" />
    </>
  );
}

import {
  ClaimDecisionButtons,
  ClaimForm,
} from "@/components/ClaimsManager";
import { getClaims } from "@/lib/gateway";
import { formatDate } from "@/lib/format";
import { requireDashboardSession } from "@/lib/auth";

export const dynamic = "force-dynamic";

export default async function ClaimsPage() {
  await requireDashboardSession();
  const result = await getClaims();

  return (
    <>
      <h1>Package claims</h1>
      <p className="muted">
        An approved claim makes a package name exclusive to the claimant.
        Claims never transfer existing releases; admins decide disputes.
      </p>
      {result.error && <div className="notice">{result.error}</div>}
      <ClaimForm />
      {result.data?.map((claim) => (
        <article key={claim.id} className="card">
          <h2>{claim.package_name}</h2>
          <p className="muted">
            {claim.status} · claimed by {claim.claimant} ·{" "}
            {formatDate(claim.created_at)} · {claim.reason}
          </p>
          {claim.status === "pending" && (
            <ClaimDecisionButtons claimId={claim.id} />
          )}
        </article>
      ))}
    </>
  );
}

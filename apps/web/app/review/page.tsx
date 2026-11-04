import Link from "next/link";
import { ReviewButtons } from "@/components/ReviewButtons";
import { RiskBadge, StatusBadge } from "@/components/StatusBadge";
import { getReviewQueue } from "@/lib/gateway";
import { formatDate } from "@/lib/format";
import { requireDashboardSession } from "@/lib/auth";

export const dynamic = "force-dynamic";

export default async function ReviewPage() {
  await requireDashboardSession();
  const result = await getReviewQueue();

  return (
    <>
      <h1>Review queue</h1>
      <p className="muted">
        Pending releases awaiting a reviewer decision within policy.
      </p>
      {result.error && <div className="notice">{result.error}</div>}
      {result.data && result.data.length === 0 && (
        <p className="muted">No releases are pending review.</p>
      )}
      {result.data?.map((release) => (
        <article key={release.id} className="card">
          <h2>
            <Link href={`/releases/${release.id}`}>
              {release.packageName} <span className="version">v{release.version}</span>
            </Link>
          </h2>
          <p>
            <StatusBadge status={release.status} />{" "}
            <RiskBadge risk={release.riskTier} />{" "}
            <span className="muted">
              Published {formatDate(release.createdAt)} by {release.publisher}
            </span>
          </p>
          <ReviewButtons releaseId={release.id} />
        </article>
      ))}
    </>
  );
}

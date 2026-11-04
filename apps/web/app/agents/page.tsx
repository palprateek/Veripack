import Link from "next/link";
import { getAgentReviews, getReleases } from "@/lib/gateway";
import { requireDashboardSession } from "@/lib/auth";

export const dynamic = "force-dynamic";

export default async function AgentsPage() {
  await requireDashboardSession();
  const releases = await getReleases();
  const pending = (releases.data ?? []).filter(
    (release) => release.status === "pending",
  );
  const panels = await Promise.all(
    pending.slice(0, 20).map(async (release) => ({
      release,
      panel: await getAgentReviews(release.id),
    })),
  );

  return (
    <>
      <h1>Agent panel</h1>
      <p className="muted">
        Specialized agents post advisory recommendations bounded by policy.
        Agents never approve a release — humans decide in the review queue.
      </p>
      {releases.error && <div className="notice">{releases.error}</div>}
      {panels.length === 0 && (
        <p className="muted">No pending releases for the panel to review.</p>
      )}
      {panels.map(({ release, panel }) => (
        <article key={release.id} className="card">
          <h2>
            <Link href={`/releases/${release.id}`}>
              {release.packageName} <span className="version">v{release.version}</span>
            </Link>
          </h2>
          <p className="muted">
            Panel consensus:{" "}
            {panel.data?.panel.consensus ?? "split / no reviews yet"} (
            {panel.data?.panel.total ?? 0} review(s))
          </p>
          {panel.data?.reviews.map((review) => (
            <p key={review.id} className="muted">
              <strong>{review.agent_id}</strong>: {review.recommendation}
              {review.confidence !== null
                ? ` (${Math.round(review.confidence * 100)}%)`
                : ""}{" "}
              — {review.rationale}
            </p>
          ))}
        </article>
      ))}
    </>
  );
}

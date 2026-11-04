import { getInstallEvents } from "@/lib/gateway";
import { formatDate } from "@/lib/format";
import { requireDashboardSession } from "@/lib/auth";

export const dynamic = "force-dynamic";

export default async function InstallEventsPage() {
  await requireDashboardSession();
  const result = await getInstallEvents();

  return (
    <>
      <h1>Install events</h1>
      <p className="muted">
        Every allowed and blocked packument and tarball decision, in order.
      </p>
      {result.error && <div className="notice">{result.error}</div>}
      {result.data && result.data.length === 0 && (
        <p className="muted">No install events recorded yet.</p>
      )}
      {result.data?.map((event) => (
        <article key={event.id} className="card">
          <p>
            <strong>{event.decision}</strong> · {event.package_name}
            {event.version ? `@${event.version}` : ""} · {event.source}
          </p>
          <p className="muted">
            by {event.actor} · {formatDate(event.created_at)}
            {event.reason ? ` · ${event.reason}` : ""}
          </p>
        </article>
      ))}
    </>
  );
}

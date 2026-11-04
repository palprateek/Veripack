import {
  BlocklistManager,
  RevokeBlocklistButton,
} from "@/components/BlocklistManager";
import { getBlocklist } from "@/lib/gateway";
import { formatDate } from "@/lib/format";
import { requireDashboardSession } from "@/lib/auth";

export const dynamic = "force-dynamic";

export default async function BlocklistPage() {
  await requireDashboardSession();
  const result = await getBlocklist();

  return (
    <>
      <h1>Blocklist</h1>
      <p className="muted">
        Blocked packages are refused before release state, the audit cache, and
        serving. Revocation restores service.
      </p>
      {result.error && <div className="notice">{result.error}</div>}
      <BlocklistManager />
      {result.data?.map((entry) => (
        <article key={entry.id} className="card">
          <h2>
            {entry.package_name}
            {entry.version ? ` @ ${entry.version}` : " (all versions)"}
          </h2>
          <p className="muted">
            {entry.active ? "Active" : "Revoked"} · {entry.reason} · by{" "}
            {entry.created_by} · {formatDate(entry.created_at)}
          </p>
          {entry.active && <RevokeBlocklistButton entryId={entry.id} />}
        </article>
      ))}
    </>
  );
}

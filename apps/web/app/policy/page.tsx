import Link from "next/link";
import { PolicyEditor } from "@/components/PolicyEditor";
import { getPolicy } from "@/lib/gateway";
import { formatDate } from "@/lib/format";
import { requireDashboardSession } from "@/lib/auth";

export const dynamic = "force-dynamic";

export default async function PolicyPage() {
  await requireDashboardSession();
  const result = await getPolicy();
  if (!result.data) {
    return (
      <>
        <p className="breadcrumb"><Link href="/">← All releases</Link></p>
        <div className="notice">{result.error ?? "Policy could not be loaded."}</div>
      </>
    );
  }

  return (
    <>
      <p className="breadcrumb"><Link href="/">← All releases</Link></p>
      <section className="hero">
        <p className="eyebrow">Governance</p>
        <h1>Audit policy</h1>
        <p>
          Policy changes are versioned and append-only. Every future audit records
          the exact policy version that produced its verdict.
        </p>
      </section>

      <div className="layout-grid">
        <section className="panel">
          <div className="panel-header">
            <h2>Active policy</h2>
            <span className="muted mono">{result.data.active.source}</span>
          </div>
          <div className="panel-body">
            <PolicyEditor initial={result.data.active} />
          </div>
        </section>

        <section className="panel">
          <div className="panel-header">
            <h2>Policy history</h2>
            <span className="muted mono">append-only</span>
          </div>
          <div className="panel-body">
            {result.data.history.length === 0 ? (
              <p className="muted" style={{ margin: 0 }}>
                No database policy has been activated. The worker is using the
                environment fallback shown in the editor.
              </p>
            ) : (
              <div className="stack" style={{ gap: 12 }}>
                {result.data.history.map((entry) => (
                  <div className="signal" key={entry.id}>
                    <div className="signal-header">
                      <span className="signal-type mono">{entry.version}</span>
                      {entry.active && <span className="source-tag">active</span>}
                      <span className="source-tag">{entry.createdBy}</span>
                    </div>
                    <div className="signal-message">{formatDate(entry.createdAt)}</div>
                    <details style={{ marginTop: 8 }}>
                      <summary className="muted">View settings</summary>
                      <pre className="signal-evidence">{JSON.stringify(entry.policy, null, 2)}</pre>
                    </details>
                  </div>
                ))}
              </div>
            )}
          </div>
        </section>
      </div>
    </>
  );
}

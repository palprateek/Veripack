import Link from "next/link";
import { getReleases } from "@/lib/gateway";
import { formatDate } from "@/lib/format";
import {
  RiskBadge,
  StatusBadge,
  VerdictBadge,
} from "@/components/StatusBadge";
import { requireDashboardSession } from "@/lib/auth";

export const dynamic = "force-dynamic";

export default async function HomePage() {
  await requireDashboardSession();
  const result = await getReleases();
  const releases = result.data ?? [];

  const pending = releases.filter((release) => release.status === "pending").length;
  const approved = releases.filter(
    (release) => release.status === "approved" || release.status === "overridden",
  ).length;
  const blocked = releases.filter(
    (release) =>
      release.status === "rejected" || release.status === "quarantined",
  ).length;

  return (
    <>
      <section className="hero">
        <p className="eyebrow">Publish gate</p>
        <h1>Every release is audited before it is installable.</h1>
        <p>
          This registry proxies public npm and hosts private packages, but a
          private publish is stored as <strong>pending</strong> until the gate
          approves it. Low-risk releases auto-approve; everything else waits for
          a reviewer.
        </p>
      </section>

      {result.error && (
        <div className="notice">
          <strong>Dashboard cannot reach the gateway.</strong> {result.error}
          <br />
          Start the stack with <code className="code">pnpm dev</code> and confirm
          the gateway is on port 4874.
        </div>
      )}

      <section className="stats" aria-label="Release status counts">
        <div className="stat-card">
          <div className="stat-value">{pending}</div>
          <div className="stat-label">Pending review</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{approved}</div>
          <div className="stat-label">Installable</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{blocked}</div>
          <div className="stat-label">Rejected or quarantined</div>
        </div>
        <div className="stat-card">
          <div className="stat-value">{releases.length}</div>
          <div className="stat-label">Total releases</div>
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2>Releases</h2>
          <Link href="/">Refresh</Link>
        </div>

        {releases.length === 0 ? (
          <div className="empty">
            <h2>No releases yet</h2>
            <p>
              Publish the safe example to watch a low-risk release auto-approve,
              then publish the review example to exercise the approval queue.
            </p>
            <code className="code">cd examples/safe-package && npm publish</code>
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Package</th>
                  <th>Status</th>
                  <th>Risk</th>
                  <th>Safety</th>
                  <th>Intent</th>
                  <th>Policy</th>
                  <th>Published</th>
                </tr>
              </thead>
              <tbody>
                {releases.map((release) => (
                  <tr key={release.id}>
                    <td>
                      <Link
                        className="package-cell"
                        href={`/releases/${release.id}`}
                      >
                        <span className="package-name">
                          {release.packageName}
                        </span>
                        <span className="package-version">
                          v{release.version}
                        </span>
                      </Link>
                    </td>
                    <td>
                      <StatusBadge status={release.status} />
                    </td>
                    <td>
                      <RiskBadge risk={release.riskTier} />
                    </td>
                    <td>
                      <VerdictBadge
                        verdict={release.safetyVerdict}
                        kind="safety"
                      />
                    </td>
                    <td>
                      <VerdictBadge
                        verdict={release.intentVerdict}
                        kind="intent"
                      />
                    </td>
                    <td>
                      <VerdictBadge
                        verdict={release.policyResult}
                        kind="policy"
                      />
                    </td>
                    <td className="muted">{formatDate(release.createdAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="panel" style={{ marginTop: 16 }}>
        <div className="panel-header">
          <h2>Try the gate</h2>
          <span className="muted mono">M0 examples</span>
        </div>
        <div className="panel-body">
          <p className="muted" style={{ marginTop: 0 }}>
            Each example publishes to <code className="code">localhost:4874</code>{" "}
            with the development token. See <code className="code">README.md</code>{" "}
            for the full walkthrough.
          </p>
          <ul className="muted" style={{ marginBottom: 0 }}>
            <li>
              <code className="code">examples/safe-package</code> — no install
              scripts, intent present → auto-approved.
            </li>
            <li>
              <code className="code">examples/review-package</code> — benign
              postinstall script → pending human review.
            </li>
            <li>
              <code className="code">examples/risky-package</code> — downloads and
              executes remote code → rejected automatically.
            </li>
          </ul>
        </div>
      </section>
    </>
  );
}

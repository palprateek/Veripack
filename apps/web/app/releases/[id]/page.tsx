import Link from "next/link";
import { ActionButtons } from "@/components/ActionButtons";
import {
  RiskBadge,
  SeverityBadge,
  StatusBadge,
  VerdictBadge,
} from "@/components/StatusBadge";
import { getRelease } from "@/lib/gateway";
import { formatDate, shortDigest } from "@/lib/format";
import { requireDashboardSession } from "@/lib/auth";

export const dynamic = "force-dynamic";

export default async function ReleasePage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  await requireDashboardSession();
  const { id } = await params;
  const result = await getRelease(id);
  const release = result.data;

  if (!release) {
    return (
      <>
        <p className="breadcrumb">
          <Link href="/">← All releases</Link>
        </p>
        <div className="notice">
          {result.error ?? "Release not found."}
        </div>
      </>
    );
  }

  const audit = release.audit;
  const scripts = (release.manifest.scripts ?? {}) as Record<string, string>;
  const scriptEntries = Object.entries(scripts);

  return (
    <>
      <p className="breadcrumb">
        <Link href="/">← All releases</Link>
      </p>

      <header className="detail-header">
        <div>
          <h1 className="detail-title">
            {release.packageName}{" "}
            <span className="version">v{release.version}</span>
          </h1>
          <div className="detail-subtitle">
            <StatusBadge status={release.status} />
            <RiskBadge risk={release.riskTier} />
            <span>Published {formatDate(release.createdAt)}</span>
            <span>by {release.publisher}</span>
          </div>
        </div>
      </header>

      <div className="layout-grid">
        <div className="stack">
          <section className="panel">
            <div className="panel-header">
              <h2>Audit verdict</h2>
              <span className="muted mono">
                {audit
                  ? `${audit.engineVersion} · policy ${audit.policyVersion}`
                  : "audit not complete"}
              </span>
            </div>
            <div className="panel-body">
              <div className="verdict-grid">
                <div className="verdict-card">
                  <div className="verdict-label">Safety</div>
                  <VerdictBadge verdict={release.safetyVerdict} kind="safety" />
                </div>
                <div className="verdict-card">
                  <div className="verdict-label">Intent</div>
                  <VerdictBadge verdict={release.intentVerdict} kind="intent" />
                </div>
                <div className="verdict-card">
                  <div className="verdict-label">Risk tier</div>
                  <RiskBadge risk={release.riskTier} />
                </div>
                <div className="verdict-card">
                  <div className="verdict-label">Policy result</div>
                  <VerdictBadge verdict={release.policyResult} kind="policy" />
                </div>
              </div>
              {audit?.summary && (
                <p className="muted" style={{ marginBottom: 0 }}>
                  {audit.summary}
                </p>
              )}
              {!audit && (
                <p className="muted" style={{ marginBottom: 0 }}>
                  The release is queued for audit. Refresh in a moment.
                </p>
              )}
            </div>
          </section>

          <section className="panel">
            <div className="panel-header">
              <h2>Signals</h2>
              <span className="muted mono">
                {audit?.signals.length ?? 0} finding
                {(audit?.signals.length ?? 0) === 1 ? "" : "s"}
              </span>
            </div>
            <div className="panel-body">
              {audit?.signals.length ? (
                <div className="signals">
                  {audit.signals.map((signal, index) => (
                    <div className="signal" key={`${signal.type}-${index}`}>
                      <div className="signal-header">
                        <SeverityBadge severity={signal.severity} />
                        <span className="signal-type">{signal.type}</span>
                        <span className="source-tag">{signal.source}</span>
                        {signal.ruleId && (
                          <span className="source-tag">{signal.ruleId}</span>
                        )}
                      </div>
                      <div className="signal-message">{signal.message}</div>
                      {signal.evidence && (
                        <pre className="signal-evidence">
                          {JSON.stringify(signal.evidence, null, 2)}
                        </pre>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="muted" style={{ margin: 0 }}>
                  No signals recorded yet.
                </p>
              )}
            </div>
          </section>

          {audit?.llmReview && (
            <section className="panel">
              <div className="panel-header">
                <h2>LLM review</h2>
                <span className="muted mono">
                  {audit.llmReview.backend} · {audit.llmReview.model}
                </span>
              </div>
              <div className="panel-body">
                <div className="verdict-grid">
                  <div className="verdict-card">
                    <div className="verdict-label">Safety</div>
                    <VerdictBadge
                      verdict={audit.llmReview.safetyVerdict}
                      kind="safety"
                    />
                  </div>
                  <div className="verdict-card">
                    <div className="verdict-label">Intent</div>
                    <VerdictBadge
                      verdict={audit.llmReview.intentVerdict}
                      kind="intent"
                    />
                  </div>
                  <div className="verdict-card">
                    <div className="verdict-label">Risk tier</div>
                    <RiskBadge risk={audit.llmReview.riskTier} />
                  </div>
                  <div className="verdict-card">
                    <div className="verdict-label">Confidence</div>
                    <span className="mono">
                      {audit.llmReview.confidence === null
                        ? "—"
                        : `${Math.round(audit.llmReview.confidence * 100)}%`}
                    </span>
                  </div>
                </div>
                <p className="muted" style={{ margin: "12px 0 8px" }}>
                  Prompt {shortDigest(audit.llmReview.promptHash, 16)} ·{" "}
                  {audit.llmReview.citations.length} evidence citation
                  {audit.llmReview.citations.length === 1 ? "" : "s"}
                </p>
                <div className="signals">
                  {audit.llmReview.citations.map((citation, index) => (
                    <div className="signal" key={`${citation.source}-${citation.path}-${index}`}>
                      <div className="signal-header">
                        <span className="source-tag">{citation.source}</span>
                        <span className="signal-type mono">{citation.path}</span>
                      </div>
                      <div className="signal-message">{citation.explanation}</div>
                    </div>
                  ))}
                </div>
              </div>
            </section>
          )}

          <section className="panel">
            <div className="panel-header">
              <h2>Install scripts</h2>
              <span className="muted mono">
                {scriptEntries.length} present
              </span>
            </div>
            <div className="panel-body">
              {scriptEntries.length ? (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Lifecycle</th>
                        <th>Command</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scriptEntries.map(([name, command]) => (
                        <tr key={name}>
                          <td className="mono">{name}</td>
                          <td className="mono">{command}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="muted" style={{ margin: 0 }}>
                  No install lifecycle scripts are present in the manifest.
                </p>
              )}
            </div>
          </section>

          {release.approvals.some(
            (approval) => approval.reviewerId === release.publisher,
          ) && (
            <div className="notice" role="alert">
              Warning: this release was self-approved by its publisher under
              the organization self-approval policy.
            </div>
          )}

          <section className="panel">
            <div className="panel-header">
              <h2>Approval history</h2>
              <span className="muted mono">
                {release.approvals.length} decision
                {release.approvals.length === 1 ? "" : "s"}
              </span>
            </div>
            <div className="panel-body">
              {release.approvals.length ? (
                <div className="stack" style={{ gap: 12 }}>
                  {release.approvals.map((approval) => (
                    <div className="signal" key={approval.id}>
                      <div className="signal-header">
                        <StatusBadge
                          status={
                            approval.decision === "approved"
                              ? "approved"
                              : approval.decision === "rejected"
                                ? "rejected"
                                : approval.decision === "yanked"
                                  ? "yanked"
                                  : approval.decision === "quarantined"
                                    ? "quarantined"
                                    : "overridden"
                          }
                        />
                        <span className="signal-type">
                          {approval.reviewerId}
                        </span>
                        <span className="source-tag">
                          {approval.reviewerType}
                        </span>
                        <span className="source-tag">
                          {formatDate(approval.createdAt)}
                        </span>
                      </div>
                      <div className="signal-message">
                        {approval.reason ?? "No reason recorded."}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="muted" style={{ margin: 0 }}>
                  No approval decisions recorded.
                </p>
              )}
            </div>
          </section>

          <section className="panel">
            <div className="panel-header">
              <h2>Audit events</h2>
              <span className="muted mono">append-only</span>
            </div>
            <div className="panel-body">
              {release.events.length ? (
                <ol className="timeline">
                  {release.events.map((event) => (
                    <li className="timeline-item" key={event.id}>
                      <div className="timeline-action">{event.action}</div>
                      <div className="timeline-meta">
                        {event.actor} · {formatDate(event.createdAt)}
                      </div>
                    </li>
                  ))}
                </ol>
              ) : (
                <p className="muted" style={{ margin: 0 }}>
                  No events recorded.
                </p>
              )}
            </div>
          </section>
        </div>

        <div className="stack">
          <section className="panel">
            <div className="panel-header">
              <h2>Actions</h2>
            </div>
            <div className="panel-body">
              <ActionButtons
                releaseId={release.id}
                status={release.status}
                hasAudit={Boolean(audit)}
                sandboxEnabled={process.env.SANDBOX_UI_ENABLED === "true"}
              />
              <p className="muted" style={{ marginBottom: 0, fontSize: 12 }}>
                Publishers cannot approve their own releases. Deterministic
                critical findings auto-reject and can only be overridden by an
                admin with a reason.
              </p>
            </div>
          </section>

          <section className="panel">
            <div className="panel-header">
              <h2>Release intent</h2>
            </div>
            <div className="panel-body">
              {release.intent ? (
                <p style={{ margin: 0 }}>{release.intent}</p>
              ) : (
                <p className="muted" style={{ margin: 0 }}>
                  No intent supplied. Add{" "}
                  <code className="code">
                    {'"trust": { "intent": "..." }'}
                  </code>{" "}
                  to <code className="code">package.json</code> before publishing.
                </p>
              )}
            </div>
          </section>

          <section className="panel">
            <div className="panel-header">
              <h2>Release identity</h2>
            </div>
            <div className="panel-body">
              <div className="meta-grid">
                <div className="meta-item">
                  <div className="meta-label">Tarball digest</div>
                  <div className="meta-value mono" title={release.tarballDigest}>
                    {shortDigest(release.tarballDigest, 20)}
                  </div>
                </div>
                <div className="meta-item">
                  <div className="meta-label">Publisher</div>
                  <div className="meta-value">{release.publisher}</div>
                </div>
                <div className="meta-item">
                  <div className="meta-label">Integrity</div>
                  <div className="meta-value mono">
                    {release.integrity
                      ? `${release.integrity.slice(0, 24)}…`
                      : "—"}
                  </div>
                </div>
                <div className="meta-item">
                  <div className="meta-label">Created</div>
                  <div className="meta-value">
                    {formatDate(release.createdAt)}
                  </div>
                </div>
              </div>
            </div>
          </section>

          {audit && (
            <section className="panel">
              <div className="panel-header">
                <h2>Structured change set</h2>
              </div>
              <div className="panel-body">
                <pre className="signal-evidence">
                  {JSON.stringify(audit.changeSet, null, 2)}
                </pre>
              </div>
            </section>
          )}
        </div>
      </div>
    </>
  );
}

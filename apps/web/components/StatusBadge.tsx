import type { ReleaseStatus } from "@veripack/shared";
import { titleCase } from "@/lib/format";

export function StatusBadge({ status }: { status: ReleaseStatus }) {
  return (
    <span className={`badge badge-status badge-${status}`}>
      {titleCase(status)}
    </span>
  );
}

export function RiskBadge({ risk }: { risk: string | null }) {
  if (!risk) return <span className="muted">—</span>;
  return <span className={`badge badge-risk badge-${risk}`}>{titleCase(risk)}</span>;
}

export function SeverityBadge({ severity }: { severity: string }) {
  const tone = severity === "info" || severity === "low" ? "info" : severity;
  return (
    <span className={`badge badge-risk badge-${tone}`}>
      {titleCase(severity)}
    </span>
  );
}

export function VerdictBadge({
  verdict,
  kind,
}: {
  verdict: string | null;
  kind: "safety" | "intent" | "policy";
}) {
  if (!verdict) return <span className="muted">—</span>;
  return (
    <span className={`badge badge-verdict badge-${kind}-${verdict}`}>
      {titleCase(verdict)}
    </span>
  );
}

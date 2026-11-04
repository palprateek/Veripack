"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import type { PolicyConfig } from "@/lib/gateway";

interface PolicyDiffEntry {
  path: string;
  before: unknown;
  after: unknown;
  direction: "tighten" | "loosen";
}

interface PolicyImpactEntry {
  releaseId: string;
  packageName: string;
  version: string;
  candidateRiskTier: string;
  candidatePolicyResult: string;
  candidateAutoApprove: boolean;
  changed: boolean;
}

interface PolicyPreview {
  direction: "tighten" | "loosen" | "none";
  diff: PolicyDiffEntry[];
  impact: PolicyImpactEntry[];
}

export function PolicyEditor({ initial }: { initial: PolicyConfig }) {
  const router = useRouter();
  const [version, setVersion] = useState(initial.version);
  const [policyText, setPolicyText] = useState(
    JSON.stringify(initial, null, 2),
  );
  const [reason, setReason] = useState("");
  const [preview, setPreview] = useState<PolicyPreview | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  function readPolicy(): PolicyConfig | null {
    try {
      const parsed = JSON.parse(policyText) as PolicyConfig;
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        setError("Policy must be a JSON object.");
        return null;
      }
      return { ...parsed, version: version.trim() };
    } catch (parseError) {
      setError(
        parseError instanceof Error
          ? `Policy JSON is invalid: ${parseError.message}`
          : "Policy JSON is invalid.",
      );
      return null;
    }
  }

  async function requestPolicy(dryRun: boolean) {
    setBusy(true);
    setError(null);
    setMessage(null);
    const policy = readPolicy();
    if (!policy) {
      setBusy(false);
      return;
    }
    if (!version.trim()) {
      setError("A policy version is required.");
      setBusy(false);
      return;
    }

    try {
      const response = await fetch("/api/policy", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          version: version.trim(),
          policy,
          reason: reason.trim() || undefined,
          dryRun,
        }),
      });
      const body = (await response.json().catch(() => ({}))) as {
        error?: string;
        direction?: PolicyPreview["direction"];
        diff?: PolicyDiffEntry[];
        impact?: PolicyImpactEntry[];
        request?: { id: string; status: string };
        policy?: { version: string };
      };
      if (!response.ok) {
        setError(body.error ?? `Policy update failed (${response.status}).`);
        return;
      }

      setPreview({
        direction: body.direction ?? "none",
        diff: body.diff ?? [],
        impact: body.impact ?? [],
      });

      if (dryRun) {
        setMessage("Preview only. No policy was activated.");
      } else if (response.status === 202) {
        setMessage(
          "Loosening request recorded. A second admin must approve it, or it can be approved after the 24-hour cooling-off.",
        );
        router.refresh();
      } else {
        setMessage(
          `Policy ${body.policy?.version ?? version} activated. New audits will use this version.`,
        );
        router.refresh();
      }
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Request failed.");
    } finally {
      setBusy(false);
    }
  }

  const changedImpact = preview?.impact.filter((entry) => entry.changed) ?? [];

  return (
    <form
      className="policy-form"
      onSubmit={(event) => {
        event.preventDefault();
        void requestPolicy(false);
      }}
    >
      <label className="field-label" htmlFor="policy-version">
        New policy version
      </label>
      <input
        id="policy-version"
        className="input mono"
        value={version}
        onChange={(event) => setVersion(event.target.value)}
        required
        maxLength={120}
      />

      <label className="field-label" htmlFor="policy-json">
        Policy JSON (strict schema)
      </label>
      <textarea
        id="policy-json"
        className="input mono"
        value={policyText}
        onChange={(event) => setPolicyText(event.target.value)}
        rows={20}
        spellCheck={false}
      />

      <label className="field-label" htmlFor="policy-reason">
        Reason (required for loosening)
      </label>
      <textarea
        id="policy-reason"
        className="input"
        value={reason}
        onChange={(event) => setReason(event.target.value)}
        rows={2}
        maxLength={2000}
      />

      <div className="policy-options">
        <p className="muted" style={{ margin: 0 }}>
          The safety floor is not configurable: critical findings block, missing
          intent never auto-approves, an unavailable previous artifact never
          auto-approves, and binary or obfuscated content never auto-approves.
        </p>
      </div>

      {preview && (
        <div className="signal">
          <div className="signal-header">
            <span className="signal-type mono">Parsed diff</span>
            <span className="source-tag">{preview.direction}</span>
          </div>
          {preview.diff.length === 0 ? (
            <div className="signal-message">No semantic change.</div>
          ) : (
            <ul className="signal-message">
              {preview.diff.map((entry) => (
                <li key={entry.path}>
                  <span className="mono">{entry.path}</span>{" "}
                  {JSON.stringify(entry.before)} → {JSON.stringify(entry.after)}{" "}
                  <em>({entry.direction})</em>
                </li>
              ))}
            </ul>
          )}
          <div className="signal-message">
            {changedImpact.length === 0
              ? "No pending release changes result."
              : `${changedImpact.length} pending release${
                  changedImpact.length === 1 ? "" : "s"
                } would change result.`}
          </div>
          {changedImpact.map((entry) => (
            <div className="signal-message" key={entry.releaseId}>
              <span className="mono">
                {entry.packageName}@{entry.version}
              </span>{" "}
              → {entry.candidateRiskTier}/{entry.candidatePolicyResult}
              {entry.candidateAutoApprove ? " (auto-approve)" : ""}
            </div>
          ))}
        </div>
      )}

      <div className="policy-options">
        <button
          className="button"
          disabled={busy}
          type="button"
          onClick={() => void requestPolicy(true)}
        >
          {busy ? "Checking…" : "Preview diff and impact"}
        </button>
        <button className="button button-approve" disabled={busy} type="submit">
          {busy ? "Activating…" : "Activate / request change"}
        </button>
      </div>
      {message && <p className="form-success">{message}</p>}
      {error && <p className="form-error">{error}</p>}
    </form>
  );
}

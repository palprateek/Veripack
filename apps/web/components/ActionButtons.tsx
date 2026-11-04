"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import type { ReleaseStatus } from "@veripack/shared";

type Action = "approve" | "reject" | "yank" | "quarantine" | "sandbox";

const REASON_REQUIRED: Action[] = ["reject", "yank", "quarantine"];

export function ActionButtons({
  releaseId,
  status,
  hasAudit,
  sandboxEnabled,
}: {
  releaseId: string;
  status: ReleaseStatus;
  hasAudit: boolean;
  sandboxEnabled: boolean;
}) {
  const router = useRouter();
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState<Action | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const canApprove =
    hasAudit && (status === "pending" || status === "rejected");
  const canReject = status === "pending";
  const canYank = status === "approved" || status === "overridden";
  const canQuarantine = status !== "quarantined";
  const canSandbox = sandboxEnabled;

  if (!canApprove && !canReject && !canYank && !canQuarantine && !canSandbox) {
    return <p className="muted">No actions available for this release.</p>;
  }

  async function act(action: Action) {
    setError(null);
    setMessage(null);

    if (REASON_REQUIRED.includes(action) && !reason.trim()) {
      setError(`A reason is required to ${action} a release.`);
      return;
    }

    if (
      action === "quarantine" &&
      !window.confirm(
        "Quarantine blocks this release for every resolution, including existing lockfiles. Continue?",
      )
    ) {
      return;
    }

    if (action === "sandbox" && !window.confirm("Run the package entrypoint in the isolated, network-disabled sandbox?")) {
      return;
    }

    setBusy(action);
    try {
      const response = await fetch(
        `/api/releases/${encodeURIComponent(releaseId)}/${action}`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ reason: reason.trim() || undefined }),
        },
      );

      const body = (await response.json().catch(() => ({}))) as {
        error?: string;
      };

      if (!response.ok) {
        setError(body.error ?? `Request failed with status ${response.status}.`);
        return;
      }

      setReason("");
      if (action === "sandbox") setMessage("Sandbox completed. Review the recorded event below.");
      router.refresh();
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : "The gateway request failed.",
      );
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="actions">
      <label className="field-label" htmlFor="decision-reason">
        Decision reason
      </label>
      <textarea
        id="decision-reason"
        className="textarea"
        value={reason}
        onChange={(event) => setReason(event.target.value)}
        placeholder="Required for reject, yank, quarantine, and override."
        rows={3}
      />

      {status === "pending" && !hasAudit && (
        <p className="muted" style={{ margin: 0, fontSize: 12 }}>
          Approval unlocks when the audit finishes. Rejection is available
          immediately.
        </p>
      )}

      <div className="action-buttons">
        {canApprove && (
          <button
            className="button button-approve"
            disabled={busy !== null}
            onClick={() => void act("approve")}
          >
            {busy === "approve"
              ? "Approving…"
              : status === "rejected"
                ? "Override & approve"
                : "Approve release"}
          </button>
        )}
        {canReject && (
          <button
            className="button button-reject"
            disabled={busy !== null}
            onClick={() => void act("reject")}
          >
            {busy === "reject" ? "Rejecting…" : "Reject"}
          </button>
        )}
        {canYank && (
          <button
            className="button button-warn"
            disabled={busy !== null}
            onClick={() => void act("yank")}
          >
            {busy === "yank" ? "Yanking…" : "Yank"}
          </button>
        )}
        {canQuarantine && (
          <button
            className="button button-danger"
            disabled={busy !== null}
            onClick={() => void act("quarantine")}
          >
            {busy === "quarantine" ? "Quarantining…" : "Quarantine"}
          </button>
        )}
        {canSandbox && (
          <button
            className="button button-warn"
            disabled={busy !== null}
            onClick={() => void act("sandbox")}
          >
            {busy === "sandbox" ? "Running sandbox…" : "Run sandbox"}
          </button>
        )}
      </div>

      {error && <p className="form-error">{error}</p>}
      {message && <p className="form-success">{message}</p>}
    </div>
  );
}

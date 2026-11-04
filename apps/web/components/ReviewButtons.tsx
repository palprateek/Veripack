"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

export function ReviewButtons({ releaseId }: { releaseId: string }) {
  const router = useRouter();
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function act(action: "approve" | "reject") {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const response = await fetch(`/api/review/${releaseId}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ action, reason: reason || null }),
      });
      const payload = (await response.json().catch(() => ({}))) as {
        error?: string;
        decision?: string;
      };
      if (!response.ok) {
        setError(payload.error ?? `Review action failed (${response.status}).`);
        return;
      }
      setMessage(
        payload.decision === "awaiting_second_reviewer"
          ? "Approval recorded. A second distinct reviewer is required."
          : `Release ${action === "approve" ? "approved" : "rejected"}.`,
      );
      router.refresh();
    } catch (requestError) {
      setError(
        requestError instanceof Error ? requestError.message : "Request failed.",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <input
        aria-label="Review reason"
        placeholder="Reason (required to reject)"
        value={reason}
        onChange={(event) => setReason(event.target.value)}
      />{" "}
      <button type="button" disabled={busy} onClick={() => void act("approve")}>
        Approve
      </button>{" "}
      <button type="button" disabled={busy} onClick={() => void act("reject")}>
        Reject
      </button>
      {message && <p className="muted">{message}</p>}
      {error && <p className="error">{error}</p>}
    </div>
  );
}

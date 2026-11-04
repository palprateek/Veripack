"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

async function postClaim(payload: Record<string, unknown>) {
  const response = await fetch("/api/claims", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  const body = (await response.json().catch(() => ({}))) as { error?: string };
  if (!response.ok) throw new Error(body.error ?? `Failed (${response.status}).`);
}

export function ClaimForm() {
  const router = useRouter();
  const [packageName, setPackageName] = useState("");
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await postClaim({ packageName, reason });
      setPackageName("");
      setReason("");
      router.refresh();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={(event) => void submit(event)}>
      <input
        aria-label="Package name"
        placeholder="@scope/package"
        value={packageName}
        onChange={(event) => setPackageName(event.target.value)}
        required
      />{" "}
      <input
        aria-label="Reason"
        placeholder="Why is this name yours?"
        value={reason}
        onChange={(event) => setReason(event.target.value)}
        required
      />{" "}
      <button type="submit" disabled={busy}>
        Request claim
      </button>
      {error && <p className="error">{error}</p>}
    </form>
  );
}

export function ClaimDecisionButtons({ claimId }: { claimId: string }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);

  async function decide(decision: "approve" | "reject") {
    setBusy(true);
    try {
      await postClaim({ claimId, decision });
      router.refresh();
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <button type="button" disabled={busy} onClick={() => void decide("approve")}>
        Approve claim
      </button>{" "}
      <button type="button" disabled={busy} onClick={() => void decide("reject")}>
        Reject claim
      </button>
    </>
  );
}

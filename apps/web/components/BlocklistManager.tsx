"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

export function BlocklistManager() {
  const router = useRouter();
  const [packageName, setPackageName] = useState("");
  const [version, setVersion] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const response = await fetch("/api/blocklist", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          packageName,
          version: version || null,
          reason,
        }),
      });
      const payload = (await response.json().catch(() => ({}))) as {
        error?: string;
      };
      if (!response.ok) {
        setError(payload.error ?? `Blocklist update failed (${response.status}).`);
        return;
      }
      setPackageName("");
      setVersion("");
      setReason("");
      router.refresh();
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
        aria-label="Version (optional)"
        placeholder="Version (optional)"
        value={version}
        onChange={(event) => setVersion(event.target.value)}
      />{" "}
      <input
        aria-label="Reason"
        placeholder="Reason"
        value={reason}
        onChange={(event) => setReason(event.target.value)}
        required
      />{" "}
      <button type="submit" disabled={busy}>
        Block package
      </button>
      {error && <p className="error">{error}</p>}
    </form>
  );
}

export function RevokeBlocklistButton({ entryId }: { entryId: string }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);

  async function revoke() {
    setBusy(true);
    try {
      await fetch("/api/blocklist", {
        method: "DELETE",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ entryId, reason: "Revoked from dashboard." }),
      });
      router.refresh();
    } finally {
      setBusy(false);
    }
  }

  return (
    <button type="button" disabled={busy} onClick={() => void revoke()}>
      Revoke
    </button>
  );
}

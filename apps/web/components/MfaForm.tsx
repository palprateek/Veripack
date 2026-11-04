"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

export function MfaForm({ mode }: { mode: "login" | "step-up" }) {
  const router = useRouter();
  const [secret, setSecret] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  async function post(payload: Record<string, unknown>) {
    const response = await fetch("/api/auth/mfa", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    const body = (await response.json().catch(() => ({}))) as Record<
      string,
      unknown
    > & { error?: string };
    if (!response.ok) {
      throw new Error(body.error ?? `Request failed (${response.status}).`);
    }
    return body;
  }

  async function enroll() {
    setBusy(true);
    setError(null);
    try {
      const body = await post({ action: "enroll" });
      setSecret(typeof body.secretBase32 === "string" ? body.secretBase32 : null);
      setMessage("Add this secret to your authenticator, then verify a code.");
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Failed.");
    } finally {
      setBusy(false);
    }
  }

  async function verify(action: "verify" | "challenge" | "step-up") {
    setBusy(true);
    setError(null);
    try {
      const body = await post({ action, code });
      if (Array.isArray(body.recoveryCodes)) {
        setRecoveryCodes(body.recoveryCodes as string[]);
      }
      setMessage(
        action === "step-up"
          ? "Step-up complete for 15 minutes."
          : "MFA verified. You are signed in.",
      );
      if (action !== "step-up") router.push("/");
      router.refresh();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      {mode === "login" && !secret && (
        <button type="button" disabled={busy} onClick={() => void enroll()}>
          Enroll MFA
        </button>
      )}
      {secret && (
        <p>
          Secret: <code>{secret}</code>
        </p>
      )}
      <input
        aria-label="One-time code"
        placeholder="123456"
        value={code}
        onChange={(event) => setCode(event.target.value)}
      />{" "}
      {mode === "step-up" ? (
        <button type="button" disabled={busy} onClick={() => void verify("step-up")}>
          Verify step-up
        </button>
      ) : (
        <>
          <button type="button" disabled={busy} onClick={() => void verify("verify")}>
            Verify enrollment
          </button>{" "}
          <button type="button" disabled={busy} onClick={() => void verify("challenge")}>
            Verify code
          </button>
        </>
      )}
      {recoveryCodes && (
        <div className="notice">
          <p>Save these one-time recovery codes:</p>
          <ul>
            {recoveryCodes.map((recoveryCode) => (
              <li key={recoveryCode}>
                <code>{recoveryCode}</code>
              </li>
            ))}
          </ul>
        </div>
      )}
      {message && <p className="muted">{message}</p>}
      {error && <p className="error">{error}</p>}
    </div>
  );
}

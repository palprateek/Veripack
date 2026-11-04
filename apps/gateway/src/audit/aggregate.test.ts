import { describe, expect, it } from "vitest";
import type { Signal } from "@veripack/shared";
import { mergeLlmReview } from "./aggregate.js";
import { DEFAULT_AUDIT_POLICY } from "./policy.js";
import type { StaticAuditResult } from "./static.js";

const baseResult: StaticAuditResult = {
  policyVersion: DEFAULT_AUDIT_POLICY.version,
  safetyVerdict: "clear",
  intentVerdict: "matches",
  riskTier: "low",
  policyResult: "pass",
  signals: [],
  changeSet: { engine: "static" },
  summary: "Eligible for auto-approval.",
  autoApprove: true,
};

const review = {
  backend: "openai-compatible",
  safetyVerdict: "review" as const,
  intentVerdict: "mismatch" as const,
  riskTier: "high" as const,
  confidence: 0.8,
  citations: [
    {
      source: "signal" as const,
      path: "install_script_added",
      explanation: "The install script needs review.",
    },
  ],
  model: "test-model",
  promptHash: "a".repeat(64),
  sampling: { temperature: 0 },
  tokenCost: 100,
};

const context = {
  policy: DEFAULT_AUDIT_POLICY,
  intent: "Add a helper.",
  firstRelease: false,
  previousUnavailable: false,
};

describe("LLM audit aggregation", () => {
  it("escalates review without allowing an LLM to auto-approve", () => {
    const result = mergeLlmReview(baseResult, review, context);

    expect(result.riskTier).toBe("high");
    expect(result.policyResult).toBe("warn");
    expect(result.intentVerdict).toBe("mismatch");
    expect(result.autoApprove).toBe(false);
    expect(result.signals.some((signal) => signal.source === "llm")).toBe(true);
  });

  it("preserves deterministic blocks when the LLM is favorable", () => {
    const critical: Signal = {
      type: "install_script_download_exec",
      ruleId: "install-script-download-exec",
      severity: "critical",
      source: "deterministic",
      message: "Remote code execution pattern.",
    };
    const blocked = { ...baseResult, signals: [critical] };
    const favorable = { ...review, safetyVerdict: "clear" as const, intentVerdict: "matches" as const, riskTier: "low" as const };

    const result = mergeLlmReview(blocked, favorable, context);

    expect(result.safetyVerdict).toBe("block");
    expect(result.riskTier).toBe("critical");
    expect(result.policyResult).toBe("block");
  });

  it("re-evaluates deterministic signals when no LLM review exists", () => {
    const result = mergeLlmReview(
      baseResult,
      null,
      context,
      [
        {
          type: "sandbox_unavailable",
          ruleId: "sandbox-unavailable",
          severity: "medium",
          source: "deterministic",
          message: "The configured sandbox could not be started.",
        },
      ],
    );

    expect(result.riskTier).toBe("medium");
    expect(result.policyResult).toBe("warn");
    expect(result.autoApprove).toBe(false);
  });
});

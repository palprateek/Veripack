import type {
  IntentVerdict,
  Signal,
  SignalSeverity,
} from "@veripack/shared";
import {
  evaluatePolicy,
  type AuditPolicy,
} from "./policy.js";
import type { LlmAuditReview } from "./llm.js";
import type { StaticAuditResult } from "./static.js";

export interface LlmAggregationContext {
  policy: AuditPolicy;
  intent: string | null;
  firstRelease: boolean;
  previousUnavailable: boolean;
  packageName?: string;
  scopeKey?: string;
  diffFiles?: number;
  diffLines?: number;
}

function llmSignal(
  type: string,
  severity: SignalSeverity,
  message: string,
  review: LlmAuditReview,
): Signal {
  return {
    type,
    ruleId: type.replaceAll("_", "-"),
    severity,
    source: "llm",
    message,
    evidence: {
      backend: review.backend,
      model: review.model,
      confidence: review.confidence,
      citations: review.citations,
    },
  };
}

export function signalsFromLlmReview(review: LlmAuditReview): Signal[] {
  const signals: Signal[] = [];

  if (review.safetyVerdict === "block") {
    signals.push(
      llmSignal(
        "llm_safety_block_recommendation",
        "high",
        "The LLM recommends blocking the release; a human review is required.",
        review,
      ),
    );
  } else if (review.safetyVerdict === "review") {
    signals.push(
      llmSignal(
        "llm_safety_review",
        "medium",
        "The LLM recommends reviewing the release safety evidence.",
        review,
      ),
    );
  }

  if (review.intentVerdict === "mismatch") {
    signals.push(
      llmSignal(
        "llm_intent_mismatch",
        "high",
        "The LLM found that the release may not match its stated intent.",
        review,
      ),
    );
  }

  if (review.riskTier === "critical" || review.riskTier === "high") {
    signals.push(
      llmSignal(
        "llm_high_risk_recommendation",
        "high",
        `The LLM classified the release as ${review.riskTier} risk.`,
        review,
      ),
    );
  } else if (review.riskTier === "medium") {
    signals.push(
      llmSignal(
        "llm_medium_risk_recommendation",
        "medium",
        "The LLM classified the release as medium risk.",
        review,
      ),
    );
  }

  return signals;
}

export function mergeLlmReview(
  result: StaticAuditResult,
  review: LlmAuditReview | null,
  context: LlmAggregationContext,
  additionalSignals: Signal[] = [],
): StaticAuditResult {
  const llmSignals = review ? signalsFromLlmReview(review) : [];
  const signals = [...result.signals, ...llmSignals, ...additionalSignals];
  const policy = evaluatePolicy(
    {
      signals,
      intent: context.intent,
      firstRelease: context.firstRelease,
      previousUnavailable: context.previousUnavailable,
      packageName: context.packageName,
      scopeKey: context.scopeKey,
      diffFiles: context.diffFiles,
      diffLines: context.diffLines,
    },
    context.policy,
  );

  let intentVerdict: IntentVerdict = result.intentVerdict;
  if (review?.intentVerdict === "mismatch" || result.intentVerdict === "mismatch") {
    intentVerdict = "mismatch";
  } else if (review?.intentVerdict === "matches") {
    intentVerdict = "matches";
  }

  return {
    ...result,
    safetyVerdict: policy.safetyVerdict,
    intentVerdict,
    riskTier: policy.riskTier,
    policyResult: policy.policyResult,
    signals,
    changeSet: {
      ...result.changeSet,
      ...(review ? { llm: review } : {}),
    },
    summary: policy.summary,
    autoApprove: policy.autoApprove,
  };
}

export function llmUnavailableSignal(
  backend: string,
  error: string,
): Signal {
  return {
    type: "llm_unavailable",
    ruleId: "llm-unavailable",
    severity: "medium",
    source: "llm",
    message: "The configured LLM reviewer was unavailable; human review is required.",
    evidence: {
      backend,
      error: error.slice(0, 500),
    },
  };
}

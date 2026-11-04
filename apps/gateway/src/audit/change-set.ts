import type { NpmVersionManifest } from "../npm/payload.js";
import type { ArchiveFile, ArchiveInventory } from "./archive.js";
import { capabilitiesFromFindings, type Capability } from "./capabilities.js";
import type { ArtifactAnalysis, StaticAuditInput } from "./static.js";

export const LIFECYCLE_SCRIPTS = [
  "preinstall",
  "install",
  "postinstall",
  "prepare",
] as const;

const MAX_CHANGE_SET_PATHS = 200;

export interface FileDelta {
  added: ArchiveFile[];
  removed: ArchiveFile[];
  modified: ArchiveFile[];
}

export interface DependencyDelta {
  added: Array<{ name: string; range: string }>;
  removed: string[];
  changed: Array<{ name: string; from: string; to: string }>;
}

export interface ScriptDelta {
  current: Record<string, string>;
  added: string[];
  changed: string[];
  removed: string[];
}

export interface CapabilityDelta {
  current: Record<string, string[]>;
  added: Record<string, string[]>;
  removed: Record<string, string[]>;
}

export interface DependencyProvenance {
  bundledPackages: Array<{
    path: string;
    name: string | null;
    version: string | null;
  }>;
  installScripts: Array<{
    packagePath: string;
    packageName: string | null;
    scripts: Record<string, string>;
  }>;
  lockfiles: string[];
  lockfileInstallScripts: string[];
  truncated?: boolean;
}

/** Everything derived from comparing the current archive with its predecessor. */
export interface StaticChangeSet {
  previousManifest: NpmVersionManifest | null;
  previousAnalyzed: boolean;
  runtimeScripts: Record<string, string>;
  scripts: ScriptDelta;
  dependencies: DependencyDelta;
  dependencyEvidence: DependencyProvenance;
  delta: FileDelta;
  capabilities: CapabilityDelta;
  symlinks: ArchiveFile[];
  newLinks: ArchiveFile[];
  currentBinary: ArchiveFile[];
  changedBinary: ArchiveFile[];
  changedMinified: ArchiveFile[];
  largeSources: ArchiveFile[];
  paths: string[];
  changedBytes: number;
  changedLines: number;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function stringMap(value: unknown): Record<string, string> {
  if (!isRecord(value)) return {};
  const result: Record<string, string> = {};
  for (const [key, item] of Object.entries(value)) {
    if (typeof item === "string") result[key] = item;
  }
  return result;
}

function runtimeDependencies(manifest: NpmVersionManifest): Map<string, string> {
  const dependencies = new Map<string, string>();
  for (const field of ["dependencies", "optionalDependencies"] as const) {
    const value = manifest[field];
    if (!isRecord(value)) continue;
    for (const [name, range] of Object.entries(value)) {
      if (typeof range === "string") dependencies.set(name, range);
    }
  }
  return dependencies;
}

function dependencyDelta(
  previous: NpmVersionManifest | null,
  current: NpmVersionManifest,
): DependencyDelta {
  const previousDeps = runtimeDependencies(previous ?? {});
  const currentDeps = runtimeDependencies(current);
  const added: DependencyDelta["added"] = [];
  const removed: string[] = [];
  const changed: DependencyDelta["changed"] = [];

  for (const [name, range] of currentDeps) {
    const oldRange = previousDeps.get(name);
    if (oldRange === undefined) {
      added.push({ name, range });
    } else if (oldRange !== range) {
      changed.push({ name, from: oldRange, to: range });
    }
  }
  for (const name of previousDeps.keys()) {
    if (!currentDeps.has(name)) removed.push(name);
  }

  return { added, removed, changed };
}

function scriptDelta(
  previous: NpmVersionManifest | null,
  current: NpmVersionManifest,
): ScriptDelta {
  const previousScripts = stringMap(previous?.scripts);
  const currentScripts = stringMap(current.scripts);
  const added: string[] = [];
  const changed: string[] = [];
  const removed: string[] = [];

  for (const [name, command] of Object.entries(currentScripts)) {
    const oldCommand = previousScripts[name];
    if (oldCommand === undefined) {
      added.push(name);
    } else if (oldCommand !== command) {
      changed.push(name);
    }
  }
  for (const name of Object.keys(previousScripts)) {
    if (!(name in currentScripts)) removed.push(name);
  }

  return { current: currentScripts, added, changed, removed };
}

export function dependencyProvenance(
  inventory: ArchiveInventory,
): DependencyProvenance {
  const bundledPackages: DependencyProvenance["bundledPackages"] = [];
  const installScripts: DependencyProvenance["installScripts"] = [];
  const lockfiles: string[] = [];
  const lockfileInstallScripts: string[] = [];
  const lifecycleNames = new Set<string>(LIFECYCLE_SCRIPTS);

  for (const file of inventory.files) {
    if (file.content === null) continue;
    const lower = file.path.toLowerCase();
    if (lower.startsWith("node_modules/") && lower.endsWith("/package.json")) {
      try {
        const parsed = JSON.parse(file.content) as Record<string, unknown>;
        const scripts = stringMap(parsed.scripts);
        const packageInfo = {
          path: file.path,
          name: typeof parsed.name === "string" ? parsed.name : null,
          version: typeof parsed.version === "string" ? parsed.version : null,
        };
        bundledPackages.push(packageInfo);
        const relevant = Object.fromEntries(
          Object.entries(scripts).filter(([name]) => lifecycleNames.has(name)),
        );
        if (Object.keys(relevant).length > 0) {
          installScripts.push({
            packagePath: file.path,
            packageName: packageInfo.name,
            scripts: relevant,
          });
        }
      } catch {
        // The archive parser reports the root manifest. Vendored dependency
        // metadata is evidence, so an invalid nested manifest is retained as
        // a normal file finding rather than making the whole archive fatal.
      }
      continue;
    }

    if (
      lower === "package-lock.json" ||
      lower === "npm-shrinkwrap.json" ||
      lower === "pnpm-lock.yaml" ||
      lower === "yarn.lock"
    ) {
      lockfiles.push(file.path);
      if (lower.endsWith(".json")) {
        try {
          const parsed = JSON.parse(file.content) as Record<string, unknown>;
          const packages = parsed.packages;
          if (isRecord(packages)) {
            for (const [packagePath, metadata] of Object.entries(packages)) {
              if (isRecord(metadata) && metadata.hasInstallScript === true) {
                lockfileInstallScripts.push(packagePath || ".");
              }
            }
          }
        } catch {
          // Invalid lockfiles are reported by the package manager, not executed
          // by this analyzer. Keep the filename as the available evidence.
        }
      } else if (/hasInstallScript:\s*true/i.test(file.content)) {
        lockfileInstallScripts.push(file.path);
      }
    }
  }

  const maxEvidenceItems = 500;
  return {
    bundledPackages: bundledPackages.slice(0, maxEvidenceItems),
    installScripts: installScripts.slice(0, maxEvidenceItems),
    lockfiles: lockfiles.slice(0, maxEvidenceItems),
    lockfileInstallScripts: lockfileInstallScripts.slice(0, maxEvidenceItems),
    truncated:
      bundledPackages.length > maxEvidenceItems ||
      installScripts.length > maxEvidenceItems ||
      lockfiles.length > maxEvidenceItems ||
      lockfileInstallScripts.length > maxEvidenceItems,
  };
}

export function isDownloadAndExecute(command: string): boolean {
  const downloader = /\b(?:curl|wget|fetch|Invoke-WebRequest|iwr)\b/i;
  const executesDownloaded =
    /\|\s*(?:sudo\s+)?(?:sh|bash|zsh|fish|node|python\d*|perl|ruby|php)\b/i.test(command) ||
    /(?:^|[;&|]\s*)(?:sh|bash|zsh)\s+(?:-[a-z]+\s+)*[^\s]*\$\(\s*(?:curl|wget)\b/i.test(command) ||
    /\beval\s+["']?\$\(\s*(?:curl|wget)\b/i.test(command) ||
    /\b(?:bash|sh|zsh)\s+-c\s+["'][^"']*(?:curl|wget)\b/i.test(command);
  return downloader.test(command) && executesDownloaded;
}

function stableValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stableValue);
  if (!isRecord(value)) return value;

  const result: Record<string, unknown> = {};
  for (const key of Object.keys(value).sort()) {
    result[key] = stableValue(value[key]);
  }
  return result;
}

function selectedManifestFields(
  manifest: NpmVersionManifest,
): Record<string, unknown> {
  return stableValue({
    name: manifest.name,
    version: manifest.version,
    scripts: manifest.scripts ?? {},
    dependencies: manifest.dependencies ?? {},
    optionalDependencies: manifest.optionalDependencies ?? {},
    peerDependencies: manifest.peerDependencies ?? {},
    bin: manifest.bin ?? null,
    engines: manifest.engines ?? null,
    main: manifest.main ?? null,
    module: manifest.module ?? null,
    exports: manifest.exports ?? null,
    type: manifest.type ?? null,
  }) as Record<string, unknown>;
}

export function manifestMismatch(
  archiveManifest: Record<string, unknown> | null,
  publishedManifest: NpmVersionManifest,
): { severity: "high" | "critical"; fields: string[]; ruleId: string } | null {
  if (!archiveManifest) {
    return {
      severity: "high",
      fields: ["package.json"],
      ruleId: "archive-package-json-missing",
    };
  }

  const archive = selectedManifestFields(archiveManifest as NpmVersionManifest);
  const published = selectedManifestFields(publishedManifest);
  const archiveName = archiveManifest.name;
  const archiveVersion = archiveManifest.version;

  if (
    archiveName !== publishedManifest.name ||
    archiveVersion !== publishedManifest.version
  ) {
    return {
      severity: "critical",
      fields: ["name", "version"],
      ruleId: "archive-manifest-identity-mismatch",
    };
  }

  const fields = Object.keys(published).filter(
    (field) => JSON.stringify(archive[field]) !== JSON.stringify(published[field]),
  );

  if (fields.length > 0) {
    return { severity: "high", fields, ruleId: "archive-manifest-mismatch" };
  }
  return null;
}

export function maintainersKey(manifest: NpmVersionManifest): string | null {
  const value = manifest.maintainers;
  if (!Array.isArray(value) || value.length === 0) return null;
  return value
    .map((maintainer) => {
      if (typeof maintainer === "string") return maintainer.trim();
      if (!isRecord(maintainer)) return "";
      return `${maintainer.name ?? ""} <${maintainer.email ?? ""}>`.trim();
    })
    .filter(Boolean)
    .sort()
    .join("|");
}

function fileDelta(
  current: ArchiveInventory,
  previous: ArchiveInventory | null,
): FileDelta {
  const previousFiles = new Map(
    (previous?.files ?? []).map((file) => [file.path, file]),
  );
  const currentFiles = new Map(current.files.map((file) => [file.path, file]));
  const added: ArchiveFile[] = [];
  const removed: ArchiveFile[] = [];
  const modified: ArchiveFile[] = [];

  for (const file of current.files) {
    const old = previousFiles.get(file.path);
    if (!old) {
      added.push(file);
    } else if (old.sha256 !== file.sha256) {
      modified.push(file);
    }
  }
  for (const file of previous?.files ?? []) {
    if (!currentFiles.has(file.path)) removed.push(file);
  }

  return { added, removed, modified };
}

function changedPaths(delta: FileDelta): string[] {
  return [...delta.added, ...delta.modified, ...delta.removed].map(
    (file) => file.path,
  );
}

export function isDocsOrTest(path: string): boolean {
  const lower = path.toLowerCase();
  return (
    lower.startsWith("docs/") ||
    lower.startsWith("doc/") ||
    lower.includes("/docs/") ||
    lower.includes("/test/") ||
    lower.startsWith("test/") ||
    lower.startsWith("tests/") ||
    lower.includes("/tests/") ||
    lower.includes("__tests__/") ||
    lower.endsWith(".md") ||
    lower.endsWith(".mdx") ||
    lower.endsWith(".rst") ||
    lower.endsWith(".txt") ||
    lower.startsWith("license") ||
    lower.startsWith("readme") ||
    lower.startsWith("changelog") ||
    /(?:^|[/.-])(?:test|spec)\.[a-z0-9]+$/i.test(lower)
  );
}

function changedCapabilities(
  current: ArtifactAnalysis | null,
  previous: ArtifactAnalysis | null,
): CapabilityDelta {
  const currentMap = current
    ? capabilitiesFromFindings(current.code.findings)
    : new Map<Capability, string[]>();
  const previousMap = previous
    ? capabilitiesFromFindings(previous.code.findings)
    : new Map<Capability, string[]>();

  const toRecord = (map: Map<Capability, string[]>): Record<string, string[]> =>
    Object.fromEntries([...map.entries()].sort(([a], [b]) => a.localeCompare(b)));

  const added: Record<string, string[]> = {};
  const removed: Record<string, string[]> = {};

  for (const [capability, files] of currentMap) {
    if (!previousMap.has(capability)) added[capability] = files;
  }
  for (const [capability, files] of previousMap) {
    if (!currentMap.has(capability)) removed[capability] = files;
  }

  return {
    current: toRecord(currentMap),
    added,
    removed,
  };
}

function archiveFileSummary(file: ArchiveFile): {
  path: string;
  size: number;
  sha256: string;
  type: string;
} {
  return {
    path: file.path,
    size: file.size,
    sha256: file.sha256,
    type: file.type,
  };
}

function capped<T>(items: T[]): { items: T[]; truncated: boolean } {
  return {
    items: items.slice(0, MAX_CHANGE_SET_PATHS),
    truncated: items.length > MAX_CHANGE_SET_PATHS,
  };
}

export function buildStaticChangeSet(
  input: StaticAuditInput,
  current: ArtifactAnalysis,
  previous: ArtifactAnalysis | null,
): StaticChangeSet {
  const previousManifest = input.previous?.manifest ?? null;
  const runtimeScripts = stringMap(input.manifest.scripts);
  const scripts = scriptDelta(previousManifest, input.manifest);
  const dependencies = dependencyDelta(previousManifest, input.manifest);
  const dependencyEvidence = current.dependencyProvenance;
  const delta = fileDelta(current.inventory, previous?.inventory ?? null);
  const capabilities = changedCapabilities(current, previous);

  const symlinks = current.inventory.files.filter(
    (file) => file.type === "symlink" || file.type === "hardlink",
  );
  const previousPaths = new Set(
    (previous?.inventory.files ?? []).map((file) => `${file.path}:${file.sha256}`),
  );
  const newLinks = symlinks.filter(
    (file) => !previousPaths.has(`${file.path}:${file.sha256}`),
  );
  const currentBinary = current.inventory.files.filter(
    (file) => file.binary || file.wasm,
  );
  const changedBinary = currentBinary.filter((file) => {
    if (!previous) return true;
    const old = previous.inventory.files.find(
      (candidate) => candidate.path === file.path,
    );
    return !old || old.sha256 !== file.sha256;
  });
  const changedMinified = current.inventory.files.filter((file) => {
    if (!file.minified) return false;
    if (!previous) return true;
    const old = previous.inventory.files.find(
      (candidate) => candidate.path === file.path,
    );
    return !old;
  });
  const largeSources = current.inventory.files.filter(
    (file) =>
      /\.(?:js|cjs|mjs)$/i.test(file.path) &&
      file.content === null &&
      file.size > current.inventory.limits.maxAnalyzedFileBytes,
  );
  const paths = changedPaths(delta);
  const changedBytes = [...delta.added, ...delta.modified].reduce(
    (sum, file) => sum + file.size,
    0,
  );
  const changedLines = [...delta.added, ...delta.modified].reduce(
    (sum, file) =>
      sum + (file.content === null ? 0 : file.content.split("\n").length),
    0,
  );

  return {
    previousManifest,
    previousAnalyzed: Boolean(previous),
    runtimeScripts,
    scripts,
    dependencies,
    dependencyEvidence,
    delta,
    capabilities,
    symlinks,
    newLinks,
    currentBinary,
    changedBinary,
    changedMinified,
    largeSources,
    paths,
    changedBytes,
    changedLines,
  };
}

export function buildChangeSetPayload(
  input: StaticAuditInput,
  current: ArtifactAnalysis,
  change: StaticChangeSet,
  policyVersion: string,
): Record<string, unknown> {
  const addedFiles = capped(change.delta.added.map(archiveFileSummary));
  const removedFiles = capped(change.delta.removed.map(archiveFileSummary));
  const modifiedFiles = capped(change.delta.modified.map(archiveFileSummary));

  return {
    engine: "static",
    policy: { version: policyVersion },
    previous: input.previous
      ? {
          version: input.previous.version,
          publisher: input.previous.publisher,
          analyzed: change.previousAnalyzed,
        }
      : null,
    archive: {
      fileCount: current.inventory.files.length,
      directoryCount: current.inventory.directories.length,
      totalBytes: current.inventory.totalBytes,
      compressedBytes: current.inventory.compressedBytes,
      compressionRatio: current.inventory.compressionRatio,
      added: addedFiles.items,
      addedTruncated: addedFiles.truncated,
      removed: removedFiles.items,
      removedTruncated: removedFiles.truncated,
      modified: modifiedFiles.items,
      modifiedTruncated: modifiedFiles.truncated,
      binaryOrWasm: change.currentBinary.slice(0, 50).map((file) => file.path),
      minified: current.inventory.files
        .filter((file) => file.minified)
        .slice(0, 50)
        .map((file) => file.path),
      symlinks: change.symlinks.slice(0, 50).map((file) => ({
        path: file.path,
        type: file.type,
        target: file.linkPath,
      })),
      sourceMaps: current.inventory.files
        .filter((file) => file.sourceMap)
        .slice(0, 50)
        .map((file) => file.path),
    },
    manifest: {
      name: input.packageName,
      version: input.version,
      scripts: change.runtimeScripts,
      dependencies: stringMap(input.manifest.dependencies),
      optionalDependencies: stringMap(input.manifest.optionalDependencies),
      bins: input.manifest.bin ?? null,
      engines: input.manifest.engines ?? null,
    },
    scripts: change.scripts,
    dependencies: change.dependencies,
    dependencyProvenance: change.dependencyEvidence,
    capabilities: change.capabilities,
    code: {
      analyzedFiles: current.code.analyzedFiles,
      languages: current.code.languages,
      skippedFiles: current.code.skippedFiles.slice(0, 50),
      parseErrors: current.code.parseErrors.slice(0, 50),
    },
    limits: current.inventory.limits,
  };
}

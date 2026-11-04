import type { Signal } from "@veripack/shared";
import { findArchiveFile } from "./archive.js";
import {
  LIFECYCLE_SCRIPTS,
  isDocsOrTest,
  isDownloadAndExecute,
  maintainersKey,
  manifestMismatch,
  stringMap,
  type StaticChangeSet,
} from "./change-set.js";
import type {
  ArtifactAnalysis,
  StaticAuditInput,
} from "./static.js";

export interface StaticRuleContext {
  input: StaticAuditInput;
  current: ArtifactAnalysis;
  previous: ArtifactAnalysis | null;
  previousUnavailable: boolean;
  change: StaticChangeSet;
}

export function evaluateStaticRules(context: StaticRuleContext): Signal[] {
  const { input, current, previous, previousUnavailable, change } = context;
  const signals: Signal[] = [];
  const previousManifest = change.previousManifest;
  const runtimeScripts = change.runtimeScripts;
  const scripts = change.scripts;
  const dependencies = change.dependencies;
  const dependencyEvidence = change.dependencyEvidence;
  const capabilities = change.capabilities;
  const {
    paths,
    changedBytes,
    newLinks,
    changedBinary,
    changedMinified,
    largeSources,
  } = change;

  // Identity and provenance checks.
  if (input.firstRelease) {
    signals.push({
      type: "first_release",
      ruleId: "first-release",
      severity: "high",
      source: "deterministic",
      message:
        "This is the first release of the package in this registry. First releases require review.",
    });
  }

  if (input.previous && input.previous.publisher !== input.publisher) {
    signals.push({
      type: "publisher_changed",
      ruleId: "publisher-changed",
      severity: "high",
      source: "deterministic",
      message: `The publisher changed from ${input.previous.publisher} to ${input.publisher}.`,
      evidence: {
        previous: input.previous.publisher,
        current: input.publisher,
      },
    });
  }

  const currentMaintainers = maintainersKey(input.manifest);
  const previousMaintainers = previousManifest
    ? maintainersKey(previousManifest)
    : null;
  if (
    currentMaintainers &&
    previousMaintainers &&
    currentMaintainers !== previousMaintainers
  ) {
    signals.push({
      type: "maintainers_changed",
      ruleId: "maintainers-changed",
      severity: "high",
      source: "deterministic",
      message: "The package maintainers changed since the previous release.",
      evidence: {
        previous: previousMaintainers.split("|"),
        current: currentMaintainers.split("|"),
      },
    });
  }

  // Manifest integrity: the published manifest and the archive must describe
  // the same package. A name or version mismatch is an automatic block.
  const mismatch = manifestMismatch(
    current.inventory.packageJson,
    input.manifest,
  );
  if (mismatch) {
    signals.push({
      type: mismatch.ruleId,
      ruleId: mismatch.ruleId,
      severity: mismatch.severity,
      source: "deterministic",
      message:
        mismatch.severity === "critical"
          ? "The archive package.json identity does not match the published manifest."
          : "The archive package.json differs from the published manifest.",
      evidence: {
        fields: mismatch.fields,
        archiveName: current.inventory.packageJson?.name ?? null,
        archiveVersion: current.inventory.packageJson?.version ?? null,
        publishedName: input.packageName,
        publishedVersion: input.version,
      },
    });
  }

  if (!findArchiveFile(current.inventory, "package.json")) {
    signals.push({
      type: "missing_package_json",
      ruleId: "missing-package-json",
      severity: "high",
      source: "deterministic",
      message: "The archive does not contain a package.json at its root.",
    });
  }

  // Lifecycle scripts.
  for (const scriptName of LIFECYCLE_SCRIPTS) {
    const command = runtimeScripts[scriptName];
    if (!command?.trim()) continue;

    const critical = isDownloadAndExecute(command);
    if (critical) {
      signals.push({
        type: "install_script_download_exec",
        ruleId: "install-script-download-exec",
        severity: "critical",
        source: "deterministic",
        message: `${scriptName} downloads and executes remote code.`,
        evidence: { script: scriptName, command },
      });
      continue;
    }

    if (!previousManifest || !stringMap(previousManifest.scripts)[scriptName]) {
      signals.push({
        type: "install_script_added",
        ruleId: "install-script-added",
        severity: "high",
        source: "deterministic",
        message: `${scriptName} is a new install lifecycle script and needs review.`,
        evidence: { script: scriptName, command },
      });
    } else if (stringMap(previousManifest.scripts)[scriptName] !== command) {
      signals.push({
        type: "install_script_changed",
        ruleId: "install-script-changed",
        severity: "high",
        source: "deterministic",
        message: `${scriptName} changed and needs review.`,
        evidence: {
          script: scriptName,
          previous: stringMap(previousManifest.scripts)[scriptName],
          current: command,
        },
      });
    }
  }

  if (dependencyEvidence.installScripts.length > 0) {
    signals.push({
      type: "bundled_dependency_install_script",
      ruleId: "bundled-dependency-install-script",
      severity: "high",
      source: "deterministic",
      message: `${dependencyEvidence.installScripts.length} bundled dependency package${
        dependencyEvidence.installScripts.length === 1 ? " has" : "s have"
      } an install lifecycle script.`,
      evidence: {
        packages: dependencyEvidence.installScripts.slice(0, 20),
      },
    });
  }

  if (dependencyEvidence.lockfileInstallScripts.length > 0) {
    signals.push({
      type: "dependency_install_script_provenance",
      ruleId: "dependency-install-script-provenance",
      severity: "medium",
      source: "deterministic",
      message:
        "The published lockfile records dependencies with install scripts; review their provenance before promotion.",
      evidence: {
        lockfiles: dependencyEvidence.lockfiles,
        packages: dependencyEvidence.lockfileInstallScripts.slice(0, 50),
      },
    });
  }

  if (
    scripts.added.length === 0 &&
    scripts.changed.length === 0 &&
    Object.keys(runtimeScripts).length === 0
  ) {
    signals.push({
      type: "no_install_scripts",
      ruleId: "no-install-scripts",
      severity: "info",
      source: "deterministic",
      message: "No install lifecycle scripts are present.",
    });
  }

  // Artifact-level signals.
  if (newLinks.length > 0) {
    signals.push({
      type: "archive_links_added",
      ruleId: "archive-links-added",
      severity: "high",
      source: "deterministic",
      message: `The archive adds ${newLinks.length} symlink or hardlink ${
        newLinks.length === 1 ? "entry" : "entries"
      }.`,
      evidence: {
        links: newLinks.slice(0, 20).map((file) => ({
          path: file.path,
          type: file.type,
          target: file.linkPath,
        })),
      },
    });
  }

  if (changedBinary.length > 0) {
    signals.push({
      type: "binary_or_wasm_artifact",
      ruleId: "binary-or-wasm-artifact",
      severity: "high",
      source: "deterministic",
      message: `The archive contains ${changedBinary.length} new or changed binary/WASM ${
        changedBinary.length === 1 ? "artifact" : "artifacts"
      }.`,
      evidence: {
        files: changedBinary.slice(0, 20).map((file) => file.path),
      },
    });
  }

  if (changedMinified.length > 0) {
    signals.push({
      type: "minified_code_added",
      ruleId: "minified-code-added",
      severity: "medium",
      source: "deterministic",
      message: `The archive adds ${changedMinified.length} minified JavaScript ${
        changedMinified.length === 1 ? "file" : "files"
      }.`,
      evidence: {
        files: changedMinified.slice(0, 20).map((file) => file.path),
      },
    });
  }

  if (current.inventory.files.some((file) => file.sourceMap)) {
    signals.push({
      type: "source_maps_present",
      ruleId: "source-maps-present",
      severity: "info",
      source: "deterministic",
      message: "The archive includes source maps.",
    });
  }

  if (current.code.parseErrors.length > 0) {
    signals.push({
      type: "unparseable_javascript",
      ruleId: "unparseable-javascript",
      severity: "medium",
      source: "deterministic",
      message: `${current.code.parseErrors.length} JavaScript ${
        current.code.parseErrors.length === 1 ? "file" : "files"
      } could not be parsed.`,
      evidence: {
        files: current.code.parseErrors.slice(0, 20),
      },
    });
  }

  if (largeSources.length > 0) {
    signals.push({
      type: "large_source_not_analyzed",
      ruleId: "large-source-not-analyzed",
      severity: "medium",
      source: "deterministic",
      message: `${largeSources.length} JavaScript ${
        largeSources.length === 1 ? "file exceeds" : "files exceed"
      } the static analysis size limit.`,
      evidence: {
        files: largeSources.slice(0, 20).map((file) => ({
          path: file.path,
          size: file.size,
        })),
      },
    });
  }

  // Capability deltas. First releases are already review-tier; subsequent
  // releases only flag capabilities that did not exist in the previous version.
  if (previous && !previousUnavailable) {
    for (const [capability, files] of Object.entries(capabilities.added)) {
      const severity =
        capability === "child_process" || capability === "dynamic_code"
          ? "high"
          : capability === "network" || capability === "wasm"
            ? "medium"
            : "info";
      signals.push({
        type: `new_capability_${capability}`,
        ruleId: `new-capability-${capability}`,
        severity,
        source: "deterministic",
        message: `The release adds a ${capability} capability that was not present in the previous version.`,
        evidence: {
          capability,
          files: files.slice(0, 20),
        },
      });
    }
  }

  if (dependencies.added.length > 0) {
    signals.push({
      type: "new_dependencies",
      ruleId: "dependency-delta",
      severity: "info",
      source: "deterministic",
      message: `${dependencies.added.length} new runtime ${
        dependencies.added.length === 1 ? "dependency" : "dependencies"
      }.`,
      evidence: { added: dependencies.added },
    });
  }

  if (!input.intent) {
    signals.push({
      type: "missing_release_intent",
      ruleId: "release-intent-required",
      severity: "medium",
      source: "deterministic",
      message:
        "No release intent was supplied. Add a trust.intent note to package.json.",
    });
  }

  if (input.tarball.length > 5 * 1024 * 1024) {
    signals.push({
      type: "large_tarball",
      ruleId: "tarball-size",
      severity: "info",
      source: "deterministic",
      message: `Tarball is ${(input.tarball.length / 1024 / 1024).toFixed(1)} MiB.`,
      evidence: { bytes: input.tarball.length },
    });
  }

  if (paths.length > 200 || changedBytes > 5 * 1024 * 1024) {
    signals.push({
      type: "large_diff",
      ruleId: "large-diff",
      severity: "medium",
      source: "deterministic",
      message: `The release changes ${paths.length} files (${(
        changedBytes / 1024 / 1024
      ).toFixed(1)} MiB added or modified).`,
      evidence: { files: paths.length, changedBytes },
    });
  }

  if (previous) {
    const nonMetadata = paths.filter((path) => path !== "package.json");
    const codeChanges = nonMetadata.filter((path) => !isDocsOrTest(path));
    const onlyDocsOrTests = codeChanges.length === 0;
    if (onlyDocsOrTests && nonMetadata.length === 0) {
      signals.push({
        type: "version_bump_no_code_change",
        ruleId: "version-bump-no-code-change",
        severity: "info",
        source: "deterministic",
        message: "Only the package version changed since the previous release.",
      });
    } else if (onlyDocsOrTests) {
      signals.push({
        type: "docs_tests_only",
        ruleId: "docs-tests-only",
        severity: "info",
        source: "deterministic",
        message: "Only documentation and test files changed.",
      });
    }
  }

  return signals;
}

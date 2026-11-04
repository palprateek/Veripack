import { describe, expect, it } from "vitest";
import type { ArchiveInventory } from "./archive.js";
import {
  analyzeStaticArtifact,
  deserializeArtifactAnalysis,
  evaluateStaticAudit,
  serializeArtifactAnalysis,
  type ArtifactAnalysis,
} from "./static.js";

const inventory: ArchiveInventory = {
  files: [
    {
      path: "index.js",
      size: 22,
      sha256: "abc",
      mode: 0o644,
      type: "file",
      linkPath: null,
      binary: false,
      wasm: false,
      sourceMap: false,
      minified: false,
      content: "export const value = 1;",
    },
  ],
  directories: [],
  packageJson: { name: "@veripack/example", version: "1.0.0" },
  packageJsonPath: "package.json",
  totalBytes: 22,
  compressedBytes: 100,
  compressionRatio: 0.22,
  limits: {
    maxEntries: 20,
    maxFiles: 10,
    maxTotalBytes: 1000,
    maxFileBytes: 1000,
    maxAnalyzedFileBytes: 1000,
    maxCompressionRatio: 200,
  },
};

describe("audit artifact cache serialization", () => {
  it("does not persist analyzed source text", () => {
    const analysis: ArtifactAnalysis = {
      inventory,
      code: {
        analyzedFiles: 1,
        languages: { javascript: 1 },
        skippedFiles: [],
        parseErrors: [],
        findings: [],
      },
      dependencyProvenance: {
        bundledPackages: [
          {
            path: "node_modules/example/package.json",
            name: "example",
            version: "1.0.0",
          },
        ],
        installScripts: [
          {
            packagePath: "node_modules/example/package.json",
            packageName: "example",
            scripts: { postinstall: "node setup.js" },
          },
        ],
        lockfiles: [],
        lockfileInstallScripts: [],
      },
    };

    const cached = serializeArtifactAnalysis(analysis);
    expect(cached.inventory.files[0]?.content).toBeNull();
    expect(cached.inventory.packageJson).toEqual(inventory.packageJson);
    expect(cached.dependencyProvenance.installScripts).toHaveLength(1);
  });

  it("restores cached inventory metadata with source text omitted", () => {
    const restored = deserializeArtifactAnalysis({
      inventory,
      code: {
        analyzedFiles: 1,
        languages: { javascript: 1 },
        skippedFiles: [],
        parseErrors: [],
        findings: [],
      },
      dependencyProvenance: {
        bundledPackages: [],
        installScripts: [],
        lockfiles: [],
        lockfileInstallScripts: [],
      },
    });

    expect(restored?.inventory.files[0]?.content).toBeNull();
    expect(restored?.code.analyzedFiles).toBe(1);
  });

  it("ignores malformed cache values", () => {
    expect(deserializeArtifactAnalysis({ inventory: {} })).toBeNull();
    expect(deserializeArtifactAnalysis(null)).toBeNull();
  });

  it("can evaluate a release from source-free cached evidence", async () => {
    const tarball = await (async () => {
      const { mkdtemp, mkdir, rm, writeFile } = await import("node:fs/promises");
      const { tmpdir } = await import("node:os");
      const { join } = await import("node:path");
      const tar = await import("tar");
      const directory = await mkdtemp(join(tmpdir(), "veripack-cache-test-"));
      try {
        await mkdir(join(directory, "package"), { recursive: true });
        await writeFile(
          join(directory, "package", "package.json"),
          JSON.stringify({
            name: "@veripack/example",
            version: "1.0.0",
            trust: { intent: "Add a small helper." },
          }),
        );
        await writeFile(
          join(directory, "package", "index.js"),
          "export const value = 1;\n",
        );
        const chunks: Buffer[] = [];
        const stream = tar.c(
          { gzip: true, cwd: directory, portable: true },
          ["package"],
        );
        stream.on("data", (chunk: Buffer) => chunks.push(chunk));
        await new Promise<void>((resolve, reject) => {
          stream.on("end", resolve);
          stream.on("error", reject);
        });
        return Buffer.concat(chunks);
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    })();

    const manifest = {
      name: "@veripack/example",
      version: "1.0.0",
      trust: { intent: "Add a small helper." },
    };
    const sourceAnalysis = await analyzeStaticArtifact(tarball);
    const cachedAnalysis = deserializeArtifactAnalysis(
      serializeArtifactAnalysis(sourceAnalysis),
    );
    const result = await evaluateStaticAudit(
      {
        packageName: "@veripack/example",
        version: "1.0.0",
        publisher: "alice",
        manifest,
        intent: "Add a small helper.",
        tarball,
        previous: null,
        firstRelease: false,
      },
      {
        current: cachedAnalysis!,
        previous: null,
        previousUnavailable: false,
      },
    );

    expect(result.riskTier).toBe("low");
    expect(result.policyResult).toBe("pass");
  });
});

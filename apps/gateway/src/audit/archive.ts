import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as tar from "tar";

export interface ArchiveLimits {
  maxEntries: number;
  maxFiles: number;
  maxTotalBytes: number;
  maxFileBytes: number;
  maxAnalyzedFileBytes: number;
  maxCompressionRatio: number;
}

export const DEFAULT_ARCHIVE_LIMITS: ArchiveLimits = {
  maxEntries: 20_000,
  maxFiles: 10_000,
  maxTotalBytes: 100 * 1024 * 1024,
  maxFileBytes: 20 * 1024 * 1024,
  maxAnalyzedFileBytes: 2 * 1024 * 1024,
  maxCompressionRatio: 200,
};

export type ArchiveErrorCode =
  | "unsafe_path"
  | "limit_exceeded"
  | "invalid_archive"
  | "missing_manifest";

export class ArchiveError extends Error {
  constructor(
    readonly code: ArchiveErrorCode,
    message: string,
    readonly detail: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = "ArchiveError";
  }
}

export type ArchiveFileType =
  | "file"
  | "directory"
  | "symlink"
  | "hardlink"
  | "other";

function normalizeEntryType(rawType: string): ArchiveFileType {
  switch (rawType.toLowerCase()) {
    case "file":
      return "file";
    case "directory":
      return "directory";
    case "symlink":
    case "symboliclink":
      return "symlink";
    case "link":
    case "hardlink":
      return "hardlink";
    default:
      return "other";
  }
}

export interface ArchiveFile {
  path: string;
  size: number;
  sha256: string;
  mode: number;
  type: ArchiveFileType;
  linkPath: string | null;
  binary: boolean;
  wasm: boolean;
  sourceMap: boolean;
  minified: boolean;
  content: string | null;
}

export interface ArchiveInventory {
  files: ArchiveFile[];
  directories: string[];
  packageJson: Record<string, unknown> | null;
  packageJsonPath: string | null;
  totalBytes: number;
  compressedBytes: number;
  compressionRatio: number;
  limits: ArchiveLimits;
}

const ANALYZED_EXTENSIONS = [
  ".js",
  ".cjs",
  ".mjs",
  ".ts",
  ".cts",
  ".mts",
  ".tsx",
];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function normalizeEntryPath(rawPath: string): string {
  if (rawPath.includes("\0")) {
    throw new ArchiveError("unsafe_path", "Archive entry contains a NUL byte.", {
      path: rawPath,
    });
  }
  if (rawPath.includes("\\")) {
    throw new ArchiveError("unsafe_path", "Archive entry contains a backslash.", {
      path: rawPath,
    });
  }
  if (rawPath.startsWith("/") || /^[a-zA-Z]:/.test(rawPath)) {
    throw new ArchiveError("unsafe_path", "Archive entry uses an absolute path.", {
      path: rawPath,
    });
  }

  const trimmed = rawPath.replace(/\/+$/, "");
  if (!trimmed) {
    throw new ArchiveError("unsafe_path", "Archive entry has an empty path.", {
      path: rawPath,
    });
  }
  const segments = trimmed.split("/");
  for (const segment of segments) {
    if (segment === "" || segment === "." || segment === "..") {
      throw new ArchiveError(
        "unsafe_path",
        "Archive entry contains an empty or traversal path segment.",
        { path: rawPath },
      );
    }
  }

  // npm tarballs conventionally wrap everything in "package/". Strip that
  // single root so the report uses paths relative to the package root.
  const withoutRoot =
    segments[0] === "package" ? segments.slice(1) : segments;
  return withoutRoot.join("/");
}

function validateLinkPath(linkPath: string | undefined, entryPath: string): void {
  if (!linkPath) return;
  if (
    linkPath.includes("\0") ||
    linkPath.includes("\\") ||
    linkPath.startsWith("/") ||
    /^[a-zA-Z]:/.test(linkPath) ||
    linkPath.split("/").some((segment) => segment === "..")
  ) {
    throw new ArchiveError(
      "unsafe_path",
      "Archive link target is absolute or traverses outside the package root.",
      { path: entryPath, linkPath },
    );
  }
}

function looksBinary(buffer: Buffer): boolean {
  const sample = buffer.subarray(0, 8 * 1024);
  return sample.includes(0);
}

function looksMinified(path: string, content: string | null): boolean {
  if (path.toLowerCase().endsWith(".min.js")) return true;
  if (!content || content.length < 10_000) return false;

  const lines = content.split("\n");
  if (lines.length > 20) return false;
  return content.length / Math.max(lines.length, 1) > 500;
}

function isAnalyzableSource(path: string): boolean {
  const lower = path.toLowerCase();
  return ANALYZED_EXTENSIONS.some((extension) => lower.endsWith(extension));
}

function isMetadataFile(path: string): boolean {
  const lower = path.toLowerCase();
  return (
    lower === "package.json" ||
    (lower.startsWith("node_modules/") && lower.endsWith("/package.json")) ||
    lower === "package-lock.json" ||
    lower === "npm-shrinkwrap.json" ||
    lower === "pnpm-lock.yaml" ||
    lower === "yarn.lock"
  );
}

async function hashFile(
  entry: tar.ReadEntry,
  collectContent: boolean,
  maxAnalyzedFileBytes: number,
): Promise<{ sha256: string; content: string | null; binary: boolean }> {
  const hash = createHash("sha256");
  const chunks: Buffer[] = [];
  let collected = 0;
  let binary = false;

  for await (const chunk of entry) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    hash.update(buffer);
    if (!binary && looksBinary(buffer)) binary = true;
    if (collectContent && !binary) {
      collected += buffer.length;
      if (collected <= maxAnalyzedFileBytes) {
        chunks.push(buffer);
      }
    }
  }

  return {
    sha256: hash.digest("hex"),
    content: collectContent && !binary ? Buffer.concat(chunks).toString("utf8") : null,
    binary,
  };
}

export async function readArchive(
  tarball: Buffer,
  overrides: Partial<ArchiveLimits> = {},
): Promise<ArchiveInventory> {
  const limits: ArchiveLimits = { ...DEFAULT_ARCHIVE_LIMITS, ...overrides };
  const directory = await mkdtemp(join(tmpdir(), "veripack-audit-"));
  const archivePath = join(directory, "package.tgz");
  const files: ArchiveFile[] = [];
  const directories: string[] = [];
  let fileCount = 0;
  let entryCount = 0;
  let totalBytes = 0;
  let packageJsonRaw: string | null = null;
  let packageJsonPath: string | null = null;
  let failure: ArchiveError | null = null;

  try {
    await writeFile(archivePath, tarball, { mode: 0o600 });

    await tar.t({
      file: archivePath,
      strict: true,
      maxMetaEntrySize: 1024 * 1024,
      maxDecompressionRatio: limits.maxCompressionRatio,
      onentry(entry) {
        if (failure) {
          entry.resume();
          return;
        }

        try {
          entryCount += 1;
          if (entryCount > limits.maxEntries) {
            throw new ArchiveError(
              "limit_exceeded",
              `Archive has more than ${limits.maxEntries} entries.`,
              { path: entry.path, limit: limits.maxEntries },
            );
          }
          const logicalPath = normalizeEntryPath(entry.path);
          const type = normalizeEntryType(entry.type);

          if (type === "directory") {
            if (logicalPath) directories.push(logicalPath);
            return;
          }

          if (type !== "file" && type !== "symlink" && type !== "hardlink") {
            throw new ArchiveError(
              "invalid_archive",
              `Unsupported archive entry type "${entry.type}".`,
              { path: entry.path, type: entry.type },
            );
          }

          fileCount += 1;
          if (fileCount > limits.maxFiles) {
            throw new ArchiveError(
              "limit_exceeded",
              `Archive has more than ${limits.maxFiles} files.`,
              { path: logicalPath, limit: limits.maxFiles },
            );
          }

          if (entry.size > limits.maxFileBytes) {
            throw new ArchiveError(
              "limit_exceeded",
              `Archive entry exceeds the ${limits.maxFileBytes} byte file limit.`,
              { path: logicalPath, size: entry.size, limit: limits.maxFileBytes },
            );
          }

          totalBytes += entry.size;
          if (totalBytes > limits.maxTotalBytes) {
            throw new ArchiveError(
              "limit_exceeded",
              `Archive expands beyond the ${limits.maxTotalBytes} byte limit.`,
              { path: logicalPath, totalBytes, limit: limits.maxTotalBytes },
            );
          }

          if (type === "symlink" || type === "hardlink") {
            validateLinkPath(entry.linkpath, logicalPath);
            files.push({
              path: logicalPath,
              size: entry.size,
              sha256: "",
              mode: entry.mode ?? 0,
              type,
              linkPath: entry.linkpath ?? null,
              binary: false,
              wasm: false,
              sourceMap: false,
              minified: false,
              content: null,
            });
            return;
          }

          const collectContent =
            isMetadataFile(logicalPath) || isAnalyzableSource(logicalPath);

          return hashFile(
            entry,
            collectContent,
            limits.maxAnalyzedFileBytes,
          ).then((hashed) => {
            const content = hashed.content;
            const file: ArchiveFile = {
              path: logicalPath,
              size: entry.size,
              sha256: hashed.sha256,
              mode: entry.mode ?? 0,
              type,
              linkPath: null,
              binary: hashed.binary,
              wasm:
                logicalPath.toLowerCase().endsWith(".wasm") ||
                (content?.startsWith("\0asm") ?? false),
              sourceMap: logicalPath.toLowerCase().endsWith(".map"),
              minified: looksMinified(logicalPath, content),
              content,
            };
            files.push(file);

            if (logicalPath === "package.json" && content) {
              packageJsonRaw = content;
              packageJsonPath = logicalPath;
            }
          });
        } catch (error) {
          failure =
            error instanceof ArchiveError
              ? error
              : new ArchiveError(
                  "invalid_archive",
                  error instanceof Error ? error.message : String(error),
                );
          entry.resume();
        }
      },
    });

    if (failure) throw failure;
  } catch (error) {
    if (error instanceof ArchiveError) throw error;
    throw new ArchiveError(
      "invalid_archive",
      `The tarball could not be parsed: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }

  if (totalBytes / Math.max(tarball.length, 1) > limits.maxCompressionRatio) {
    throw new ArchiveError(
      "limit_exceeded",
      `Archive compression ratio exceeds ${limits.maxCompressionRatio}:1.`,
      {
        compressedBytes: tarball.length,
        totalBytes,
        ratio: Number((totalBytes / Math.max(tarball.length, 1)).toFixed(1)),
      },
    );
  }

  let packageJson: Record<string, unknown> | null = null;
  if (packageJsonRaw) {
    try {
      const parsed: unknown = JSON.parse(packageJsonRaw);
      packageJson = isRecord(parsed) ? parsed : null;
    } catch {
      throw new ArchiveError(
        "missing_manifest",
        "The archive package.json is not valid JSON.",
        { path: packageJsonPath },
      );
    }
  }

  files.sort((left, right) => left.path.localeCompare(right.path));

  return {
    files,
    directories: directories.sort(),
    packageJson,
    packageJsonPath,
    totalBytes,
    compressedBytes: tarball.length,
    compressionRatio: Number(
      (totalBytes / Math.max(tarball.length, 1)).toFixed(2),
    ),
    limits,
  };
}

export function findArchiveFile(
  inventory: ArchiveInventory,
  path: string,
): ArchiveFile | null {
  return inventory.files.find((file) => file.path === path) ?? null;
}

export function analyzeSourceFiles(inventory: ArchiveInventory): ArchiveFile[] {
  return inventory.files.filter(
    (file) =>
      file.type === "file" &&
      !file.binary &&
      typeof file.content === "string" &&
      isAnalyzableSource(file.path),
  );
}

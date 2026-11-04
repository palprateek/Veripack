import { parse } from "acorn";
import * as walk from "acorn-walk";
import * as ts from "typescript";
import type { ArchiveFile } from "./archive.js";

export type Capability =
  | "child_process"
  | "network"
  | "dynamic_code"
  | "filesystem"
  | "crypto"
  | "env_access"
  | "wasm";

export interface CapabilityFinding {
  capability: Capability;
  file: string;
  detail: string;
}

export interface CodeAnalysis {
  analyzedFiles: number;
  skippedFiles: string[];
  parseErrors: Array<{ file: string; message: string }>;
  findings: CapabilityFinding[];
  languages: Record<string, number>;
}

const MODULE_CAPABILITIES: Record<string, Capability[]> = {
  child_process: ["child_process"],
  "node:child_process": ["child_process"],
  vm: ["dynamic_code"],
  "node:vm": ["dynamic_code"],
  net: ["network"],
  "node:net": ["network"],
  http: ["network"],
  "node:http": ["network"],
  https: ["network"],
  "node:https": ["network"],
  http2: ["network"],
  "node:http2": ["network"],
  dns: ["network"],
  "node:dns": ["network"],
  tls: ["network"],
  "node:tls": ["network"],
  dgram: ["network"],
  "node:dgram": ["network"],
  axios: ["network"],
  "node-fetch": ["network"],
  got: ["network"],
  superagent: ["network"],
  undici: ["network"],
  fs: ["filesystem"],
  "node:fs": ["filesystem"],
  "fs/promises": ["filesystem"],
  "node:fs/promises": ["filesystem"],
  crypto: ["crypto"],
  "node:crypto": ["crypto"],
};

const MODULE_DETAIL: Record<Capability, string> = {
  child_process: "spawns a subprocess",
  network: "uses network APIs",
  dynamic_code: "evaluates code or uses the VM module",
  filesystem: "reads or writes the filesystem",
  crypto: "uses cryptography APIs",
  env_access: "reads environment variables",
  wasm: "uses WebAssembly",
};

type AnyNode = Record<string, any>;

function stringValue(node: unknown): string | null {
  if (!node || typeof node !== "object") return null;
  const candidate = node as AnyNode;
  if (candidate.type === "Literal" && typeof candidate.value === "string") {
    return candidate.value;
  }
  if (
    candidate.type === "TemplateLiteral" &&
    Array.isArray(candidate.expressions) &&
    candidate.expressions.length === 0 &&
    Array.isArray(candidate.quasis) &&
    candidate.quasis.length === 1
  ) {
    const value = candidate.quasis[0]?.value?.cooked;
    return typeof value === "string" ? value : null;
  }
  return null;
}

function propertyName(node: unknown): string | null {
  if (!node || typeof node !== "object") return null;
  const candidate = node as AnyNode;
  if (candidate.type === "Identifier" && typeof candidate.name === "string") {
    return candidate.name;
  }
  if (
    candidate.type === "MemberExpression" &&
    !candidate.computed &&
    candidate.property?.type === "Identifier"
  ) {
    return candidate.property.name;
  }
  return null;
}

function addCapability(
  findings: CapabilityFinding[],
  seen: Set<string>,
  capability: Capability,
  file: string,
  detail: string,
): void {
  const key = `${capability}:${file}`;
  if (seen.has(key)) return;
  seen.add(key);
  findings.push({ capability, file, detail });
}

function inspectModule(
  moduleName: string,
  file: string,
  findings: CapabilityFinding[],
  seen: Set<string>,
): void {
  const normalized = moduleName.replace(/^node:/, "");
  const capabilities = MODULE_CAPABILITIES[moduleName] ??
    MODULE_CAPABILITIES[normalized] ??
    [];
  for (const capability of capabilities) {
    addCapability(
      findings,
      seen,
      capability,
      file,
      `imports "${moduleName}" (${MODULE_DETAIL[capability]})`,
    );
  }
}

function inspectAst(
  ast: AnyNode,
  file: string,
  findings: CapabilityFinding[],
  seen: Set<string>,
): void {
  walk.full(ast as never, (rawNode) => {
    const node = rawNode as AnyNode;

    if (
      node.type === "ImportDeclaration" ||
      node.type === "ExportNamedDeclaration" ||
      node.type === "ExportAllDeclaration"
    ) {
      const source = stringValue(node.source);
      if (source) inspectModule(source, file, findings, seen);
      return;
    }

    if (node.type === "ImportExpression") {
      const source = stringValue(node.source);
      if (source) inspectModule(source, file, findings, seen);
      return;
    }

    if (node.type === "CallExpression") {
      const callee = node.callee;
      if (callee?.type === "Identifier") {
        if (callee.name === "require") {
          const source = stringValue(node.arguments?.[0]);
          if (source) {
            inspectModule(source, file, findings, seen);
          } else {
            addCapability(
              findings,
              seen,
              "dynamic_code",
              file,
              "calls require() with a non-literal argument",
            );
          }
        } else if (callee.name === "eval") {
          addCapability(
            findings,
            seen,
            "dynamic_code",
            file,
            "calls eval()",
          );
        } else if (callee.name === "Function") {
          addCapability(
            findings,
            seen,
            "dynamic_code",
            file,
            "calls Function()",
          );
        } else if (callee.name === "fetch") {
          addCapability(
            findings,
            seen,
            "network",
            file,
            "calls global fetch()",
          );
        }
      }

      if (
        callee?.type === "MemberExpression" &&
        propertyName(callee) === "env" &&
        callee.object?.type === "Identifier" &&
        callee.object.name === "process"
      ) {
        addCapability(
          findings,
          seen,
          "env_access",
          file,
          "reads process.env",
        );
      }
      return;
    }

    if (node.type === "NewExpression") {
      const callee = node.callee;
      if (
        callee?.type === "Identifier" &&
        (callee.name === "Function" || callee.name === "WebAssembly")
      ) {
        addCapability(
          findings,
          seen,
          callee.name === "WebAssembly" ? "wasm" : "dynamic_code",
          file,
          `constructs ${callee.name}`,
        );
      }
      return;
    }

    if (node.type === "MemberExpression") {
      if (
        propertyName(node) === "env" &&
        node.object?.type === "Identifier" &&
        node.object.name === "process"
      ) {
        addCapability(
          findings,
          seen,
          "env_access",
          file,
          "reads process.env",
        );
      }
      if (
        node.object?.type === "Identifier" &&
        node.object.name === "WebAssembly"
      ) {
        addCapability(
          findings,
          seen,
          "wasm",
          file,
          "uses WebAssembly",
        );
      }
    }
  });
}

function tsStringValue(node: ts.Node | undefined): string | null {
  if (!node) return null;
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
    return node.text;
  }
  return null;
}

function inspectTypeScriptAst(
  source: string,
  file: string,
  findings: CapabilityFinding[],
  seen: Set<string>,
): number {
  const lower = file.toLowerCase();
  const scriptKind = lower.endsWith(".tsx")
    ? ts.ScriptKind.TSX
    : ts.ScriptKind.TS;
  const ast = ts.createSourceFile(
    file,
    source,
    ts.ScriptTarget.Latest,
    true,
    scriptKind,
  );

  function visit(node: ts.Node): void {
    if (ts.isImportDeclaration(node)) {
      const moduleName = tsStringValue(node.moduleSpecifier);
      if (moduleName) inspectModule(moduleName, file, findings, seen);
    } else if (ts.isImportEqualsDeclaration(node)) {
      const reference = node.moduleReference;
      if (ts.isExternalModuleReference(reference)) {
        const moduleName = tsStringValue(reference.expression);
        if (moduleName) inspectModule(moduleName, file, findings, seen);
      }
    } else if (ts.isExportDeclaration(node) && node.moduleSpecifier) {
      const moduleName = tsStringValue(node.moduleSpecifier);
      if (moduleName) inspectModule(moduleName, file, findings, seen);
    } else if (ts.isCallExpression(node)) {
      const expression = node.expression;
      if (ts.isIdentifier(expression)) {
        if (expression.text === "require") {
          const moduleName = tsStringValue(node.arguments[0]);
          if (moduleName) {
            inspectModule(moduleName, file, findings, seen);
          } else {
            addCapability(
              findings,
              seen,
              "dynamic_code",
              file,
              "calls require() with a non-literal argument",
            );
          }
        } else if (expression.text === "eval" || expression.text === "Function") {
          addCapability(
            findings,
            seen,
            "dynamic_code",
            file,
            `calls ${expression.text}()`,
          );
        } else if (expression.text === "fetch") {
          addCapability(findings, seen, "network", file, "calls global fetch()");
        }
      } else if (expression.kind === ts.SyntaxKind.ImportKeyword) {
        const moduleName = tsStringValue(node.arguments[0]);
        if (moduleName) inspectModule(moduleName, file, findings, seen);
      }
    } else if (ts.isNewExpression(node)) {
      if (ts.isIdentifier(node.expression)) {
        if (node.expression.text === "Function") {
          addCapability(findings, seen, "dynamic_code", file, "constructs Function");
        } else if (node.expression.text === "WebAssembly") {
          addCapability(findings, seen, "wasm", file, "constructs WebAssembly");
        }
      }
    } else if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      const object = node.expression;
      const property = ts.isPropertyAccessExpression(node)
        ? node.name.text
        : tsStringValue(node.argumentExpression);
      if (ts.isIdentifier(object) && object.text === "process" && property === "env") {
        addCapability(findings, seen, "env_access", file, "reads process.env");
      }
      if (ts.isIdentifier(object) && object.text === "WebAssembly") {
        addCapability(findings, seen, "wasm", file, "uses WebAssembly");
      }
    }
    ts.forEachChild(node, visit);
  }

  visit(ast);
  const diagnostics = (ast as ts.SourceFile & { parseDiagnostics?: readonly unknown[] })
    .parseDiagnostics;
  return diagnostics?.length ?? 0;
}

export function analyzeCode(files: ArchiveFile[]): CodeAnalysis {
  const findings: CapabilityFinding[] = [];
  const seen = new Set<string>();
  const skippedFiles: string[] = [];
  const parseErrors: Array<{ file: string; message: string }> = [];
  const languages: Record<string, number> = {};
  let analyzedFiles = 0;

  for (const file of files) {
    if (file.type !== "file" || file.binary || file.content === null) {
      continue;
    }
    if (!/\.(?:js|cjs|mjs|ts|cts|mts|tsx)$/i.test(file.path)) {
      continue;
    }

    if (/\.(?:ts|cts|mts|tsx)$/i.test(file.path)) {
      try {
        const diagnostics = inspectTypeScriptAst(
          file.content,
          file.path,
          findings,
          seen,
        );
        analyzedFiles += 1;
        languages.typescript = (languages.typescript ?? 0) + 1;
        if (diagnostics > 0) {
          parseErrors.push({
            file: file.path,
            message: `${diagnostics} TypeScript syntax diagnostic${diagnostics === 1 ? "" : "s"}.`,
          });
        }
      } catch (error) {
        parseErrors.push({
          file: file.path,
          message: error instanceof Error ? error.message : String(error),
        });
        skippedFiles.push(file.path);
      }
      continue;
    }

    const sourceType = file.path.toLowerCase().endsWith(".mjs")
      ? "module"
      : file.path.toLowerCase().endsWith(".cjs")
        ? "script"
        : "module";

    let ast: AnyNode | null = null;
    for (const candidate of sourceType === "module" ? ["module", "script"] : ["script", "module"]) {
      try {
        ast = parse(file.content, {
          ecmaVersion: "latest",
          sourceType: candidate as "module" | "script",
          allowHashBang: true,
          allowAwaitOutsideFunction: true,
          allowReturnOutsideFunction: true,
        }) as unknown as AnyNode;
        break;
      } catch {
        // Try the other source type before recording a parse error.
      }
    }

    if (!ast) {
      parseErrors.push({
        file: file.path,
        message: "File could not be parsed as JavaScript.",
      });
      skippedFiles.push(file.path);
      continue;
    }

    analyzedFiles += 1;
    languages.javascript = (languages.javascript ?? 0) + 1;
    inspectAst(ast, file.path, findings, seen);
  }

  return {
    analyzedFiles,
    skippedFiles,
    parseErrors,
    findings,
    languages,
  };
}

export function capabilitiesFromFindings(
  findings: CapabilityFinding[],
): Map<Capability, string[]> {
  const result = new Map<Capability, string[]>();
  for (const finding of findings) {
    const files = result.get(finding.capability) ?? [];
    if (!files.includes(finding.file)) files.push(finding.file);
    result.set(finding.capability, files);
  }
  return result;
}

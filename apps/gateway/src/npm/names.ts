const NAME_PART = /^[a-z0-9][a-z0-9._~-]*$/;
const RESERVED = new Set(["node_modules", "favicon.ico"]);

export function normalizePackageName(raw: string): string {
  let value = raw;
  try {
    value = decodeURIComponent(raw);
  } catch {
    // Keep the raw value; validation will reject it.
  }
  return value.replace(/^\/+/, "").replace(/\/+$/, "");
}

export function encodePackageName(name: string): string {
  if (name.startsWith("@")) {
    return name.replace("/", "%2f");
  }
  return encodeURIComponent(name);
}

export function isScopedName(name: string): boolean {
  return name.startsWith("@");
}

/**
 * Returns a human-readable validation error, or null when the name is valid for
 * a new package. This intentionally mirrors the npm rules that matter for a
 * private registry; it is not a full reimplementation of npm's validator.
 */
export function validatePackageName(name: string): string | null {
  if (name.length === 0) return "Package name is empty.";
  if (name.length > 214) return "Package name must be 214 characters or fewer.";
  if (name !== name.toLowerCase()) {
    return "Package name must be lowercase.";
  }
  if (name !== name.trim()) {
    return "Package name cannot have leading or trailing whitespace.";
  }
  if (RESERVED.has(name)) {
    return `Package name "${name}" is reserved.`;
  }

  if (name.startsWith("@")) {
    const parts = name.split("/");
    if (parts.length !== 2) {
      return 'Scoped package names must look like "@scope/name".';
    }
    const [scope, local] = parts;
    if (!scope || scope.length < 2 || !NAME_PART.test(scope.slice(1))) {
      return "Invalid scope in package name.";
    }
    if (!local || !NAME_PART.test(local)) {
      return "Invalid package name after the scope.";
    }
    return null;
  }

  if (!NAME_PART.test(name)) {
    return "Package name contains invalid characters or starts with a disallowed character.";
  }
  return null;
}

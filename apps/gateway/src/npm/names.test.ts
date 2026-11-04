import { describe, expect, it } from "vitest";
import {
  encodePackageName,
  isScopedName,
  normalizePackageName,
  validatePackageName,
} from "./names.js";

describe("normalizePackageName", () => {
  it("decodes npm's encoded scope separator", () => {
    expect(normalizePackageName("@veripack%2fsafe-package")).toBe(
      "@veripack/safe-package",
    );
  });

  it("strips surrounding slashes", () => {
    expect(normalizePackageName("/@veripack/safe-package/")).toBe(
      "@veripack/safe-package",
    );
  });
});

describe("encodePackageName", () => {
  it("encodes only the scope separator for scoped names", () => {
    expect(encodePackageName("@veripack/safe-package")).toBe(
      "@veripack%2fsafe-package",
    );
  });

  it("leaves unscoped names alone", () => {
    expect(encodePackageName("safe-package")).toBe("safe-package");
  });
});

describe("validatePackageName", () => {
  it("accepts scoped and unscoped lowercase names", () => {
    expect(validatePackageName("@veripack/safe-package")).toBeNull();
    expect(validatePackageName("safe-package")).toBeNull();
  });

  it("rejects uppercase names", () => {
    expect(validatePackageName("@Veripack/Safe-Package")).not.toBeNull();
  });

  it("rejects names that start with a dot or underscore", () => {
    expect(validatePackageName(".hidden")).not.toBeNull();
    expect(validatePackageName("_private")).not.toBeNull();
  });

  it("rejects malformed scoped names", () => {
    expect(validatePackageName("@veripack")).not.toBeNull();
    expect(validatePackageName("@veripack/safe/package")).not.toBeNull();
  });

  it("identifies scoped names", () => {
    expect(isScopedName("@veripack/safe-package")).toBe(true);
    expect(isScopedName("safe-package")).toBe(false);
  });
});

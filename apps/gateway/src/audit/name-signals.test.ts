import { describe, expect, it } from "vitest";
import { detectNameSignals, levenshtein } from "./name-signals.js";

describe("name squatting signals", () => {
  it("computes edit distances", () => {
    expect(levenshtein("react", "react")).toBe(0);
    expect(levenshtein("react", "raect")).toBe(1);
    expect(levenshtein("lodash", "lodahs")).toBe(1);
  });

  it("flags typosquat suspects against popular packages", () => {
    const signals = detectNameSignals("lodahs", []);
    expect(signals.some((s) => s.type === "possible_typosquat")).toBe(true);
  });

  it("flags confusable collisions against existing names", () => {
    const signals = detectNameSignals("@acme/my-pkg", ["@acme/my_pkg"]);
    expect(
      signals.some((s) => s.type === "name_collision_confusable"),
    ).toBe(true);
  });

  it("stays silent for the package itself and unrelated names", () => {
    expect(detectNameSignals("react", [])).toEqual([]);
    expect(detectNameSignals("@acme/widget", ["@acme/database"])).toEqual([]);
  });
});

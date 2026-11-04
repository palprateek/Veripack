import { describe, expect, it } from "vitest";
import { runSandbox } from "./sandbox.js";
import { config as defaultConfig } from "./config.js";

describe("dynamic sandbox boundary", () => {
  it("never executes anything when the sandbox is disabled", async () => {
    const result = await runSandbox(Buffer.from("not-an-archive"), {
      ...defaultConfig,
      SANDBOX_MODE: "disabled",
    });
    expect(result).toMatchObject({ enabled: false, runtime: null, image: null });
  });
});

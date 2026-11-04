import { describe, expect, it } from "vitest";
import {
  isDownloadable,
  isInstallable,
  isVisibleInPackument,
} from "./registry-view.js";

describe("registry view", () => {
  it("treats only replayed approved or overridden releases as installable", () => {
    expect(
      isInstallable({ status: "approved", replay_state: "succeeded" }),
    ).toBe(true);
    expect(
      isInstallable({ status: "overridden", replay_state: "succeeded" }),
    ).toBe(true);
    expect(isInstallable({ status: "approved", replay_state: "failed" })).toBe(
      false,
    );
    expect(isInstallable({ status: "pending", replay_state: "not_started" })).toBe(
      false,
    );
  });

  it("never downloads yanked or otherwise non-installable releases", () => {
    expect(isDownloadable({ status: "yanked", replay_state: "succeeded" })).toBe(
      false,
    );
    expect(isDownloadable({ status: "yanked", replay_state: "failed" })).toBe(
      false,
    );
    expect(isDownloadable({ status: "quarantined", replay_state: "succeeded" })).toBe(
      false,
    );
    expect(isDownloadable({ status: "approved", replay_state: "failed" })).toBe(
      false,
    );
    expect(isDownloadable({ status: "rejected", replay_state: "not_started" })).toBe(
      false,
    );
  });

  it("hides yanked and non-installable releases from the packument", () => {
    expect(
      isVisibleInPackument({ status: "approved", replay_state: "succeeded" }),
    ).toBe(true);
    expect(
      isVisibleInPackument({ status: "yanked", replay_state: "succeeded" }),
    ).toBe(false);
    expect(
      isVisibleInPackument({ status: "approved", replay_state: "failed" }),
    ).toBe(false);
    expect(
      isVisibleInPackument({ status: "quarantined", replay_state: "succeeded" }),
    ).toBe(false);
  });
});

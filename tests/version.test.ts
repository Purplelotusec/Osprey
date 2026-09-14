import { describe, expect, it } from "vitest";
import { evaluateVersionStatus } from "../src/vulnerability/version.js";
import type { OsvAffected } from "../src/vulnerability/osv.js";

function affected(overrides: Partial<OsvAffected> = {}): OsvAffected {
  return {
    package: { ecosystem: "npm", name: "demo" },
    ...overrides,
  };
}

describe("OSV npm version evaluation", () => {
  it("handles exact affected and patched boundaries", () => {
    const advisory = affected({ ranges: [{ type: "SEMVER", events: [{ introduced: "1.2.0" }, { fixed: "1.2.10" }] }] });
    expect(evaluateVersionStatus("1.2.9", [advisory])).toBe("affected");
    expect(evaluateVersionStatus("1.2.10", [advisory])).toBe("not_affected");
  });

  it("handles versions below and above an affected range", () => {
    const advisory = affected({ ranges: [{ type: "SEMVER", events: [{ introduced: "1.2.0" }, { fixed: "1.3.0" }] }] });
    expect(evaluateVersionStatus("1.1.9", [advisory])).toBe("not_affected");
    expect(evaluateVersionStatus("1.3.1", [advisory])).toBe("not_affected");
  });

  it("handles inclusive introduced and last-affected boundaries", () => {
    const advisory = affected({ ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "1.0.0" }, { last_affected: "1.0.5" }] }] });
    expect(evaluateVersionStatus("1.0.0", [advisory])).toBe("affected");
    expect(evaluateVersionStatus("1.0.5", [advisory])).toBe("affected");
    expect(evaluateVersionStatus("1.0.6", [advisory])).toBe("not_affected");
  });

  it("handles multiple affected ranges and exact version lists", () => {
    const advisory = affected({
      versions: ["4.0.0"],
      ranges: [{ type: "SEMVER", events: [{ introduced: "2.0.0" }, { fixed: "2.1.0" }, { introduced: "3.0.0" }, { fixed: "3.1.0" }] }],
    });
    expect(evaluateVersionStatus("2.0.5", [advisory])).toBe("affected");
    expect(evaluateVersionStatus("2.1.0", [advisory])).toBe("not_affected");
    expect(evaluateVersionStatus("4.0.0", [advisory])).toBe("affected");
  });

  it("returns unknown for invalid versions and unusable ranges", () => {
    const advisory = affected({ ranges: [{ type: "SEMVER", events: [{ introduced: "not-a-version" }] }] });
    expect(evaluateVersionStatus("not-a-version", [advisory])).toBe("unknown");
    expect(evaluateVersionStatus("1.0.0", [advisory])).toBe("unknown");
    expect(evaluateVersionStatus("1.0.0", [affected()])).toBe("unknown");
  });
});

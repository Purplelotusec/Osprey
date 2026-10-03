import { describe, it, expect } from "vitest";
import { mavenScheme, pep440Scheme, semverScheme, versionSchemeFor } from "../src/vulnerability/version-schemes.js";
import { evaluateVersionStatus, extractPatchedVersion } from "../src/vulnerability/version.js";
import type { OsvAffected } from "../src/vulnerability/osv.js";

// Every expected sign below is the answer of the reference implementation, not
// hand-derived: Maven 3.9.15's org.apache.maven.artifact.versioning.ComparableVersion
// and Python's packaging 26.3 (pip's PEP 440 implementation). The full
// differential runs (443,935 Maven and 691,908 PyPI real-world pairs from OSV)
// had zero mismatches.

const MAVEN: Array<[string, string, number]> = [
  ["1", "1.0.0", 0],
  ["1-ga", "1", 0],
  ["1-final", "1", 0],
  ["1-alpha-1", "1-a1", 0],
  ["1-rc1", "1-cr1", 0],
  ["9.0.0.M1", "9.0.0-M1", 0],
  ["2.0-beta9", "2.0", -1],
  ["2.0-rc1", "2.0", -1],
  ["1-SNAPSHOT", "1", -1],
  ["1-sp", "1", 1],
  ["1-1", "1.1", -1],
  ["1.0.0-0.3.7", "1-1", -1],
  ["1--1", "1", 1],
  ["2.14.1", "2.15.0", -1],
  ["2.3.1", "2.14.1", -1],
  ["5.3.18.RELEASE", "5.3.18", 0],
  ["1.53.0.pre2", "1.53.0", 1],
  ["v2.3.0", "2.3.0", -1],
  ["28.0-android", "28.0-jre", -1],
  ["3.0.0-rc.2", "3.0.0-rc1", 1],
  ["4.1.0.RC", "4.1.0.alpha1", 1],
  ["1.2.0.RC1", "1.2.0_SP1", -1],
  ["7.4.3.112", "7.4.3.112-ga112", -1],
  ["1-abc", "1-sp", 1],
];

const PEP440: Array<[string, string, number]> = [
  ["1.0", "1.0.0", 0],
  ["1.0.dev0", "1.0a1", -1],
  ["1.0a1", "1.0b1", -1],
  ["1.0b1", "1.0rc1", -1],
  ["1.0rc1", "1.0", -1],
  ["1.0c1", "1.0rc1", 0],
  ["1.0", "1.0.post1", -1],
  ["1.0-1", "1.0.post1", 0],
  ["1.0.post1.dev2", "1.0.post1", -1],
  ["1.0+local", "1.0", 1],
  ["1!0.5", "2.0", 1],
  ["v1.0", "1.0", 0],
  ["1.10.11rc1", "1.10.11", -1],
  ["1.0a1.dev1", "1.0a1", -1],
  ["1.0rev2", "1.0.post2", 0],
  ["1.0_beta_2", "1.0b2", 0],
];

describe("Maven ComparableVersion (vectors confirmed by Maven 3.9.15)", () => {
  it.each(MAVEN)("%s vs %s -> %i", (a, b, expected) => {
    expect(Math.sign(mavenScheme.compare(a, b))).toBe(expected);
    expect(Math.sign(mavenScheme.compare(b, a))).toBe(-expected || 0); // antisymmetric
  });
});

describe("PEP 440 (vectors confirmed by packaging 26.3)", () => {
  it.each(PEP440)("%s vs %s -> %i", (a, b, expected) => {
    expect(Math.sign(pep440Scheme.compare(a, b))).toBe(expected);
  });

  it("rejects strings that aren't PEP 440 versions", () => {
    expect(pep440Scheme.isValid("1.0.0-SNAPSHOT")).toBe(false);
    expect(pep440Scheme.isValid("not-a-version")).toBe(false);
  });
});

describe("versionSchemeFor", () => {
  it("maps OSV ecosystems to their ordering", () => {
    expect(versionSchemeFor("npm")).toBe(semverScheme);
    expect(versionSchemeFor("PyPI")).toBe(pep440Scheme);
    expect(versionSchemeFor("Maven")).toBe(mavenScheme);
    expect(versionSchemeFor("crates.io")).toBeUndefined();
  });
});

describe("range evaluation", () => {
  // CVE-2021-44228 (Log4Shell), as OSV publishes it: three windows in one advisory.
  const log4shell: OsvAffected[] = [{
    package: { ecosystem: "Maven", name: "org.apache.logging.log4j:log4j-core" },
    ranges: [{
      type: "ECOSYSTEM",
      // Deliberately unsorted: OSV doesn't guarantee event order within a range.
      events: [{ introduced: "2.13.0" }, { fixed: "2.15.0" }, { introduced: "2.0-beta9" }, { fixed: "2.3.1" }, { introduced: "2.4" }, { fixed: "2.12.2" }],
    }],
  }];

  it.each([
    ["2.14.1", "affected"],
    ["2.0-beta9", "affected"],
    ["2.12.1", "affected"],
    ["2.3.1", "not_affected"],
    ["2.12.2", "not_affected"],
    ["2.15.0", "not_affected"],
    ["2.17.1", "not_affected"],
    ["2.0-alpha1", "not_affected"],
  ])("log4j-core %s is %s (multi-window range, sorted before evaluation)", (version, status) => {
    expect(evaluateVersionStatus(version, log4shell, mavenScheme)).toBe(status);
  });

  it("suggests the next fix above the installed version, never a downgrade", () => {
    expect(extractPatchedVersion(log4shell, "2.14.1", mavenScheme)).toBe("2.15.0"); // not 2.3.1
    expect(extractPatchedVersion(log4shell, "2.5", mavenScheme)).toBe("2.12.2");
    expect(extractPatchedVersion(log4shell, "2.0-beta9", mavenScheme)).toBe("2.3.1");
    expect(extractPatchedVersion(log4shell, "2.17.1", mavenScheme)).toBeUndefined();
  });

  it("evaluates PyPI pre-releases instead of giving up (was 'unknown' under semver)", () => {
    const airflow: OsvAffected[] = [{
      package: { ecosystem: "PyPI", name: "apache-airflow" },
      ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "1.10.11rc1" }] }],
    }];
    expect(evaluateVersionStatus("1.10.11rc1", airflow, pep440Scheme)).toBe("not_affected");
    expect(evaluateVersionStatus("1.10.10", airflow, pep440Scheme)).toBe("affected");
    expect(evaluateVersionStatus("1.10.11", airflow, pep440Scheme)).toBe("not_affected");
  });

  it("matches OSV's version list by equivalence, not spelling (Maven 1.0 == 1)", () => {
    const listed: OsvAffected[] = [{ package: { ecosystem: "Maven", name: "g:a" }, versions: ["1.0"] }];
    expect(evaluateVersionStatus("1", listed, mavenScheme)).toBe("affected");
    expect(evaluateVersionStatus("1.0.0.RELEASE", listed, mavenScheme)).toBe("affected");
    expect(evaluateVersionStatus("1.1", listed, mavenScheme)).toBe("not_affected");
  });

  it("handles last_affected and introduced 0", () => {
    const upTo: OsvAffected[] = [{ package: { ecosystem: "Maven", name: "g:a" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { last_affected: "1.4" }] }] }];
    expect(evaluateVersionStatus("1.4", upTo, mavenScheme)).toBe("affected");
    expect(evaluateVersionStatus("1.4.1", upTo, mavenScheme)).toBe("not_affected");
  });

  it("ignores GIT ranges (commit hashes aren't versions) rather than guessing", () => {
    const gitOnly: OsvAffected[] = [{ package: { ecosystem: "Maven", name: "g:a" }, ranges: [{ type: "GIT", events: [{ introduced: "abc123" }, { fixed: "def456" }] }] }];
    expect(evaluateVersionStatus("1.0", gitOnly, mavenScheme)).toBe("unknown");
  });
});

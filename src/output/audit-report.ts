import type { SecurityFinding, SboimResult } from "../vulnerability/types.js";
import { osvPackage } from "../vulnerability/osv.js";
import { colors, symbols, colorize, bold, dim, section, formatTable } from "./formatter.js";

export interface AuditReportOptions {
  verbose?: boolean;
}

export function printAuditReport(result: SboimResult, options: AuditReportOptions = {}): void {
  const { verbose = false } = options;

  // Header
  console.log(section("Vulnerability Audit"));
  console.log(packagesCheckedText(result));
  console.log();

  // Overall status - VERSION-AWARE
  const hasAffected = result.affectedCount > 0;
  const hasNotAffected = result.notAffectedCount > 0;
  const hasUnknown = result.unknownCount > 0;
  const incomplete = isIncomplete(result);

  if (incomplete) {
    // Zero findings from a run that never finished is not a clean result — never render it as one.
    console.log(colorize(`${symbols.error} Audit incomplete — results cannot be trusted (see Errors below)`, "red"));
    console.log();
  } else if (!hasAffected && !hasNotAffected && !hasUnknown) {
    console.log(colorize(`${symbols.success} No vulnerabilities found`, "green"));
  } else {
    if (hasAffected) {
      console.log(colorize(`${symbols.error} ${result.affectedCount} vulnerable package(s)`, "red"));
    }
    if (hasNotAffected) {
      console.log(colorize(`${symbols.success} ${result.notAffectedCount} safe (patched)`, "green"));
    }
    if (hasUnknown) {
      console.log(colorize(`${symbols.warning} ${result.unknownCount} unknown`, "yellow"));
    }
    console.log();
  }

  if (result.matches.length > 0) {
    console.log(section("Known Exploited Vulnerabilities"));
    printFindings(result.matches, { verbose });
  }

  // Warnings
  if (result.warnings.length > 0) {
    console.log(section("Warnings"));
    for (const warning of result.warnings) {
      console.log(colorize(`  ${symbols.warning} ${warning}`, "yellow"));
    }
  }

  // Errors
  if (result.errors.length > 0) {
    console.log(section("Errors"));
    for (const error of result.errors) {
      console.log(colorize(`  ${symbols.error} ${error}`, "red"));
    }
  }

  // Summary (only show if verbose or has issues)
  if (verbose || incomplete || result.affectedCount > 0 || result.matches.length > 0) {
    console.log(section("Summary"));
    console.log(`Status: ${statusLabel(result)}`);
    console.log();
  }
}

/** "120 packages checked", or "118 of 120 packages checked" when some couldn't be (see the warnings). */
export function packagesCheckedText(result: SboimResult): string {
  const checked = result.checkedComponentCount ?? result.sbomComponentCount;
  return checked === result.sbomComponentCount
    ? `${checked} packages checked`
    : `${checked} of ${result.sbomComponentCount} packages checked`;
}

/** A run that hit an error (failed stage) never produced a complete answer, whatever its counts say. */
export function isIncomplete(result: SboimResult): boolean {
  return result.errors.length > 0 || Object.values(result.stages).some((stage) => stage.status === "failed");
}

/**
 * The verdict shown to people (terminal report, CI job summary). An affected
 * installed version is a FAILED audit even when the run's `status` is
 * "passed" because --fail-on-high wasn't set — that flag only controls the exit code.
 */
export function overallStatus(result: SboimResult): "PASSED" | "FAILED" | "FAILED (audit incomplete)" {
  if (isIncomplete(result)) return "FAILED (audit incomplete)";
  if (result.status === "failed" || result.affectedCount > 0) return "FAILED";
  return "PASSED";
}

function statusLabel(result: SboimResult): string {
  const status = overallStatus(result);
  return colorize(status, status === "PASSED" ? "green" : "red");
}

interface FindingsPrintOptions {
  verbose: boolean;
}

function printFindings(findings: SecurityFinding[], options: FindingsPrintOptions): void {
  for (let i = 0; i < findings.length; i++) {
    const finding = findings[i]!;
    const num = i + 1;

    console.log();
    console.log(bold(`${num}. ${finding.kevEntry.cveId}`));
    console.log(`   Component: ${colorize(finding.component.name, "cyan")}${finding.component.version ? `@${finding.component.version}` : ""}`);

    if (finding.component.purl) {
      console.log(`   PURL: ${dim(finding.component.purl)}`);
    }

    console.log(`   Vulnerability: ${finding.kevEntry.vulnerabilityName}`);

    // Version status
    const versionStatusText = getVersionStatusText(finding);
    console.log(`   Version Status: ${versionStatusText}`);

    // KEV details
    console.log(`   Product: ${finding.kevEntry.product} (${finding.kevEntry.vendorProject})`);
    console.log(`   Description: ${finding.kevEntry.shortDescription}`);

    if (finding.kevEntry.requiredAction) {
      console.log(`   Required Action: ${colorize(finding.kevEntry.requiredAction, "yellow")}`);
    }

    if (finding.kevEntry.dueDate) {
      console.log(`   Due Date: ${finding.kevEntry.dueDate}`);
    }

    if (finding.kevEntry.knownRansomwareUse === "Known") {
      console.log(`   ${colorize("⚠ Known Ransomware Use", "red")}`);
    }

    // Advisory information
    if (finding.advisoryIds.length > 0) {
      console.log(`   Advisories: ${finding.advisoryIds.join(", ")}`);
    }

    // Remediation - show patched version if available
    console.log();
    if (finding.versionStatus === "affected" && finding.patchedVersion) {
      console.log(colorize(`   ${symbols.warning} REMEDIATION:`, "yellow"));
      console.log(`   ${colorize(`Current: ${finding.currentVersion ?? "unknown"}`, "red")} → ${colorize(`Upgrade to: ${finding.patchedVersion}+`, "green")}`);
      const hint = upgradeHint(finding, finding.patchedVersion);
      if (hint) console.log(`   ${dim(hint)}`);
    } else if (finding.versionStatus === "affected") {
      console.log(colorize(`   ${symbols.warning} RECOMMENDED ACTION:`, "yellow"));
      console.log(`   ${dim("Update to the latest patched version immediately.")}`);
      console.log(`   ${dim(`Check security advisories for ${finding.component.name}`)}`);
    } else if (finding.versionStatus === "not_affected") {
      console.log(colorize(`   ${symbols.success} SAFE:`, "green"));
      console.log(`   ${dim("Your current version is not affected by this vulnerability.")}`);
    }

    // Verbose mode
    if (options.verbose) {
      console.log(`   Confidence: ${finding.confidence}`);
      console.log(`   Matched On: ${finding.matchedOn}`);
      console.log(`   Date Added to KEV: ${finding.kevEntry.dateAdded}`);
    }
  }
  console.log();
}

/** How to apply the fix in the package's ecosystem. */
function upgradeHint(finding: SecurityFinding, version: string): string | undefined {
  const pkg = osvPackage(finding.component);
  if (pkg?.ecosystem === "npm") return `Run: npm install ${pkg.name}@${version}`;
  if (pkg?.ecosystem === "PyPI") return `Run: pip install ${pkg.name}==${version}`;
  // Maven has no install command: the version is declared in pom.xml (or a parent POM / imported BOM).
  if (pkg?.ecosystem === "Maven") return `Update ${pkg.name} to ${version} in pom.xml (or the dependencyManagement / BOM that sets it)`;
  return undefined;
}

function getVersionStatusText(finding: SecurityFinding): string {
  const version = finding.component.version;

  if (!version) {
    return colorize("UNKNOWN (no version specified)", "yellow");
  }

  switch (finding.versionStatus) {
    case "affected":
      return colorize(`AFFECTED (${version} is vulnerable)`, "red");
    case "not_affected":
      return colorize(`NOT AFFECTED (${version} is safe)`, "green");
    case "unknown":
      return colorize(`UNKNOWN (cannot determine if ${version} is affected)`, "yellow");
    default:
      return colorize("UNKNOWN", "yellow");
  }
}

export function printAuditSummary(result: SboimResult): void {
  const hasAffected = result.affectedCount > 0;
  const hasMatches = result.matches.length > 0;

  if (isIncomplete(result)) {
    console.log(colorize(`\n${symbols.error} Audit incomplete — results cannot be trusted`, "red"));
    for (const error of result.errors) {
      console.log(colorize(`  ${symbols.error} ${error}`, "red"));
    }
    console.log();
    return;
  }

  if (!hasMatches) {
    console.log(colorize(`\n${symbols.success} No active exploitable vulnerabilities detected\n`, "green"));
  } else {
    // Show status breakdown
    console.log();
    if (hasAffected) {
      console.log(colorize(`${symbols.error} ${result.affectedCount} VULNERABLE package(s) actively exploited`, "red"));
    } else {
      console.log(colorize(`${symbols.success} All packages are safe (patched or unaffected)`, "green"));
    }

    if (result.notAffectedCount > 0) {
      console.log(colorize(`${symbols.success} ${result.notAffectedCount} package(s) have CVE but are SAFE (patched)`, "green"));
    }
    if (result.unknownCount > 0) {
      console.log(colorize(`${symbols.warning} ${result.unknownCount} package(s) with UNKNOWN version status`, "yellow"));
    }
    console.log();

    // Show detailed table for affected packages
    if (hasAffected) {
      const affected = result.matches.filter((m) => m.versionStatus === "affected");
      const rows = affected.map((finding) => [
        colorize(symbols.error, "red"),
        finding.component.name,
        finding.currentVersion ?? "unknown",
        finding.kevEntry.cveId,
        finding.patchedVersion ? colorize(finding.patchedVersion, "green") : "see advisory",
      ]);

      console.log(formatTable([
        [bold(""), bold("Package"), bold("Current"), bold("CVE"), bold("Patched Version")],
        ...rows,
      ], { indent: 2 }));
      console.log();
    }
  }

  // Even the short view must say when results rest on cached or partial data.
  for (const warning of result.warnings) {
    console.log(colorize(`${symbols.warning} ${warning}`, "yellow"));
  }
  if (result.warnings.length > 0) console.log();
}

function getVersionStatusBadge(status: SecurityFinding["versionStatus"]): string {
  switch (status) {
    case "affected":
      return colorize("AFFECTED", "red");
    case "not_affected":
      return colorize("SAFE", "green");
    case "unknown":
      return colorize("UNKNOWN", "yellow");
    default:
      return colorize("UNKNOWN", "yellow");
  }
}

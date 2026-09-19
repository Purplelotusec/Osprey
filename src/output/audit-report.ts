import type { SecurityFinding, SboimResult } from "../vulnerability/types.js";
import { colors, symbols, colorize, bold, dim, section, formatTable } from "./formatter.js";

export interface AuditReportOptions {
  verbose?: boolean;
  showLowConfidence?: boolean;
}

export function printAuditReport(result: SboimResult, options: AuditReportOptions = {}): void {
  const { verbose = false, showLowConfidence = true } = options;

  // Header
  console.log(section("SBOM Vulnerability Audit Report"));
  console.log(`Subject: ${dim(result.subjectName)}`);
  console.log(`Components analyzed: ${result.sbomComponentCount}`);
  console.log(`KEV entries checked: ${result.kevSnapshot.entryCount} (as of ${result.kevSnapshot.dateReleased ?? result.kevSnapshot.fetchedAt})`);
  console.log();

  // Overall status
  const hasHighConfidenceMatches = result.highConfidenceMatchCount > 0;
  const hasLowConfidenceMatches = result.lowConfidenceMatchCount > 0;

  if (!hasHighConfidenceMatches && !hasLowConfidenceMatches) {
    console.log(colorize(`${symbols.success} No active exploitable vulnerabilities detected`, "green"));
    console.log(dim("All components are clear of known exploited vulnerabilities."));
  } else {
    console.log(colorize(`${symbols.error} Vulnerable components detected`, "red"));
    console.log();

    if (hasHighConfidenceMatches) {
      console.log(colorize(`  ${symbols.error} ${result.highConfidenceMatchCount} HIGH confidence match(es)`, "red"));
    }
    if (hasLowConfidenceMatches && showLowConfidence) {
      console.log(colorize(`  ${symbols.warning} ${result.lowConfidenceMatchCount} LOW confidence match(es)`, "yellow"));
    }
  }

  // High confidence findings
  const highConfidenceFindings = result.matches.filter((m) => m.confidence === "high");
  if (highConfidenceFindings.length > 0) {
    console.log(section("High Confidence Vulnerabilities"));
    printFindings(highConfidenceFindings, { verbose, showDetails: true });
  }

  // Low confidence findings
  if (showLowConfidence) {
    const lowConfidenceFindings = result.matches.filter((m) => m.confidence === "low");
    if (lowConfidenceFindings.length > 0) {
      console.log(section("Low Confidence Matches (Requires Manual Review)"));
      printFindings(lowConfidenceFindings, { verbose, showDetails: false });
    }
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

  // Summary
  console.log(section("Summary"));
  const status = hasHighConfidenceMatches ? colorize("FAILED", "red") : colorize("PASSED", "green");
  console.log(`Status: ${status}`);
  console.log(`Total matches: ${result.matches.length}`);
  console.log(`  - High confidence: ${result.highConfidenceMatchCount}`);
  console.log(`  - Low confidence: ${result.lowConfidenceMatchCount}`);
  console.log();
}

interface FindingsPrintOptions {
  verbose: boolean;
  showDetails: boolean;
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
    if (options.showDetails) {
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

      // Recommended action
      console.log();
      console.log(colorize(`   ${symbols.warning} RECOMMENDED ACTION:`, "yellow"));
      console.log(`   ${dim("Update to the latest patched version immediately.")}`);
      console.log(`   ${dim(`Check security advisories for ${finding.component.name}`)}`);
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
  const hasHighConfidenceMatches = result.highConfidenceMatchCount > 0;

  if (!hasHighConfidenceMatches && result.lowConfidenceMatchCount === 0) {
    console.log(colorize(`\n${symbols.success} No active exploitable vulnerabilities detected\n`, "green"));
  } else if (hasHighConfidenceMatches) {
    console.log(colorize(`\n${symbols.error} Found ${result.highConfidenceMatchCount} actively exploited vulnerable component(s)\n`, "red"));

    // Show quick list
    const highConfidence = result.matches.filter((m) => m.confidence === "high");
    const rows = highConfidence.map((finding) => [
      colorize(symbols.error, "red"),
      finding.component.name,
      finding.component.version ?? "unknown",
      finding.kevEntry.cveId,
      getVersionStatusBadge(finding.versionStatus),
    ]);

    console.log(formatTable([
      [bold(""), bold("Package"), bold("Version"), bold("CVE"), bold("Status")],
      ...rows,
    ], { indent: 2 }));
    console.log();
  }
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

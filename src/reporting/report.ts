import type { SecurityFinding, SboimResult } from "../vulnerability/types.js";

export interface SarifLog {
  version: "2.1.0";
  $schema: "https://json.schemastore.org/sarif-2.1.0.json";
  runs: Array<{
    tool: { driver: { name: "SBOIM"; informationUri: string; version: string } };
    results: SarifResult[];
  }>;
}

export interface SarifResult {
  level: "error" | "warning" | "note";
  message: { text: string };
  ruleId?: string;
}

const STATUS_ICON: Record<string, string> = {
  succeeded: "✓",
  failed: "✗",
  skipped: "—",
};

export function renderSummary(result: SboimResult): string {
  const findings = result.matches ?? [];
  const affected = findings.filter((finding) => finding.versionStatus === "affected").length;
  const notAffected = findings.filter((finding) => finding.versionStatus === "not_affected").length;
  const unknown = findings.filter((finding) => finding.versionStatus === "unknown").length;
  const status = result.status.toUpperCase();
  const lines = [
    "# SBOIM Security Scan",
    "",
    `## Overall status: ${status}`,
    "",
    "| Metric | Value |",
    "| --- | ---: |",
    `| SBOM components | ${result.sbomComponentCount} |`,
    `| KEV matches | ${findings.length} |`,
    `| High-confidence matches | ${result.highConfidenceMatchCount} |`,
    `| Affected versions | ${affected} |`,
    `| Not affected versions | ${notAffected} |`,
    `| Unknown versions | ${unknown} |`,
    `| Warnings | ${result.warnings.length} |`,
    `| Errors | ${result.errors.length} |`,
    "",
    "## Pipeline",
    "",
    "| Stage | Status | Details |",
    "| --- | --- | --- |",
  ];

  for (const [name, stage] of Object.entries(result.stages)) {
    lines.push(`| ${titleCase(name)} | ${STATUS_ICON[stage.status] ?? "—"} ${stage.status} | ${markdownText(stage.reason ?? stageDetail(name, result))} |`);
  }

  lines.push("", "## Vulnerability findings", "");
  if (findings.length === 0) {
    lines.push("No KEV findings were reported.");
  } else {
    lines.push("| Component | Version | Identity | Version status | Exploitation | Advisory / KEV |", "| --- | --- | --- | --- | --- | --- |");
    for (const finding of findings) {
      lines.push(`| ${markdownText(componentName(finding))} | ${markdownText(finding.component.version ?? "unknown")} | ${finding.identityConfidence} | ${finding.versionStatus} | ${finding.exploitationStatus} | ${markdownText(advisoryText(finding))} |`);
    }
  }

  if (result.warnings.length > 0) {
    lines.push("", "## Warnings", "", ...result.warnings.map((warning) => `- ${markdownText(warning)}`));
  }
  if (result.errors.length > 0) {
    lines.push("", "## Errors", "", ...result.errors.map((error) => `- ${markdownText(error)}`));
  }

  return `${lines.join("\n")}\n`;
}

export function toSarif(result: SboimResult): SarifLog {
  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [{
      tool: { driver: { name: "SBOIM", informationUri: "https://github.com/Purplelotusec/SBOIM", version: "0.1.0" } },
      results: (result.matches ?? []).map(toSarifResult),
    }],
  };
}

export function renderAnnotations(result: SboimResult): string[] {
  const annotations: string[] = [];
  for (const finding of result.matches ?? []) {
    if (finding.identityConfidence !== "high" && finding.versionStatus !== "affected") continue;
    const severity = finding.versionStatus === "affected" ? "error" : "warning";
    const title = finding.versionStatus === "affected" ? "Affected exploited dependency" : "High-confidence KEV match";
    annotations.push(`::${severity} title=${escapeCommand(title)}::${escapeCommand(annotationText(finding))}`);
  }
  for (const [stageName, stage] of Object.entries(result.stages)) {
    if (stage.status === "failed") {
      annotations.push(`::error title=${escapeCommand(`${titleCase(stageName)} stage failed`)}::${escapeCommand(stage.reason ?? "Stage failed")}`);
    }
  }
  return annotations;
}

function toSarifResult(finding: SecurityFinding): SarifResult {
  const ruleId = finding.kevEntry.cveId || finding.advisoryIds[0] || undefined;
  return {
    ...(ruleId ? { ruleId } : {}),
    level: finding.versionStatus === "affected" ? "error" : finding.identityConfidence === "high" ? "warning" : "note",
    message: { text: annotationText(finding) },
  };
}

function annotationText(finding: SecurityFinding): string {
  return `${componentName(finding)}@${finding.component.version ?? "unknown"}: ${finding.versionStatus}; ${finding.exploitationStatus}; identity ${finding.identityConfidence}; ${advisoryText(finding)}`;
}

function advisoryText(finding: SecurityFinding): string {
  const ids = finding.advisoryIds.length > 0 ? finding.advisoryIds.join(", ") : finding.kevEntry.cveId || "KEV entry without CVE";
  return `${ids} (${finding.kevEntry.vendorProject} ${finding.kevEntry.product}: ${finding.kevEntry.vulnerabilityName})`;
}

function componentName(finding: SecurityFinding): string {
  return `${finding.component.namespace ? `${finding.component.namespace}/` : ""}${finding.component.name}`;
}

function stageDetail(name: string, result: SboimResult): string {
  if (name === "generate") return `${result.sbomComponentCount} components`;
  if (name === "pollKev") return `${result.kevSnapshot.entryCount} catalog entries`;
  if (name === "crossCheck") return `${result.matches.length} matches`;
  if (name === "alert") return result.matches.length === 0 ? "No matches to alert" : "Findings evaluated";
  return "";
}

function titleCase(value: string): string {
  if (value === "pollKev") return "Poll KEV";
  return value.replace(/([A-Z])/g, " $1").replace(/^./, (character) => character.toUpperCase());
}

function markdownText(value: string): string {
  return value.replace(/\r?\n/g, " ").replace(/\\/g, "\\\\").replace(/\|/g, "\\|").replace(/`/g, "\\`");
}

function escapeCommand(value: string): string {
  return value.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A").replace(/:/g, "%3A").replace(/,/g, "%2C");
}

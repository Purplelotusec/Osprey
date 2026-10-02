import { isIncomplete, overallStatus } from "../output/audit-report.js";
import { parsePurl } from "../sbom/purl.js";
import type { SecurityFinding, SboimResult, VersionStatus } from "../vulnerability/types.js";

const TOOL = { name: "Osprey", informationUri: "https://github.com/Purplelotusec/Osprey", version: "0.1.0" } as const;

export interface SarifLog {
  version: "2.1.0";
  $schema: "https://json.schemastore.org/sarif-2.1.0.json";
  runs: Array<{
    tool: { driver: typeof TOOL & { rules: SarifRule[] } };
    results: SarifResult[];
  }>;
}

export interface SarifRule {
  id: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri: string;
  help: { text: string };
  properties: { tags: string[] };
}

export interface SarifResult {
  ruleId?: string;
  level: "error" | "warning" | "note";
  message: { text: string };
  locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }>;
}

/** Repository-relative dependency file per PURL type, e.g. { npm: "package-lock.json", pypi: "uv.lock" }. */
export type ManifestFiles = Partial<Record<string, string>>;

/** How loudly to report a finding: only an affected installed version is an error. */
const LEVEL: Record<VersionStatus, SarifResult["level"]> = {
  affected: "error",
  unknown: "warning",
  not_affected: "note",
};

const STATUS_ICON: Record<string, string> = {
  succeeded: "✓",
  failed: "✗",
  skipped: "—",
};

/** Markdown job summary (GitHub Actions `$GITHUB_STEP_SUMMARY`). */
export function renderSummary(result: SboimResult): string {
  const findings = result.matches;
  const lines = [
    "# Osprey: known exploited vulnerabilities",
    "",
    `## Overall status: ${overallStatus(result)}`,
    "",
    "| Metric | Value |",
    "| --- | ---: |",
    `| Packages checked | ${result.sbomComponentCount} |`,
    `| KEV catalog entries | ${result.kevSnapshot.entryCount} |`,
    `| KEV matches | ${findings.length} |`,
    `| Affected (installed version vulnerable) | ${result.affectedCount} |`,
    `| Not affected (patched) | ${result.notAffectedCount} |`,
    `| Unknown version status | ${result.unknownCount} |`,
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

  lines.push("", "## Findings", "");
  if (findings.length === 0) {
    lines.push(isIncomplete(result) ? "No findings — but the audit did not complete, so this is not a clean result." : "No KEV findings were reported.");
  } else {
    lines.push("| Component | Version | Version status | Fixed in | CVE / advisories |", "| --- | --- | --- | --- | --- |");
    for (const finding of sortByUrgency(findings)) {
      lines.push(
        `| ${markdownText(componentName(finding))} | ${markdownText(finding.component.version ?? "unknown")} | ${finding.versionStatus} | ${markdownText(finding.patchedVersion ?? "—")} | ${markdownText(advisoryText(finding))} |`
      );
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

/**
 * SARIF 2.1.0 for GitHub code scanning. Each finding is attached to the
 * dependency file its package came from (code scanning rejects results without
 * a location); each CVE becomes a rule carrying the KEV description and
 * CISA's required action.
 */
export function toSarif(result: SboimResult, manifests: ManifestFiles): SarifLog {
  const rules = new Map<string, SarifRule>();
  for (const finding of result.matches) {
    const id = finding.kevEntry.cveId;
    if (!id || rules.has(id)) continue;
    rules.set(id, {
      id,
      shortDescription: { text: finding.kevEntry.vulnerabilityName },
      fullDescription: { text: finding.kevEntry.shortDescription },
      helpUri: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}`,
      help: { text: finding.kevEntry.requiredAction ?? "Apply the vendor's fix or upgrade to a patched version." },
      properties: { tags: ["security", "known-exploited-vulnerability"] },
    });
  }

  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [{
      tool: { driver: { ...TOOL, rules: [...rules.values()] } },
      results: result.matches.map((finding) => toSarifResult(finding, manifests)),
    }],
  };
}

/** GitHub Actions workflow annotations: affected and unknown findings, plus failed stages. */
export function renderAnnotations(result: SboimResult): string[] {
  const annotations: string[] = [];
  for (const finding of sortByUrgency(result.matches)) {
    if (finding.versionStatus === "not_affected") continue; // patched: nothing to act on
    const severity = finding.versionStatus === "affected" ? "error" : "warning";
    const title = finding.versionStatus === "affected" ? "Exploited vulnerability in installed dependency" : "Exploited vulnerability, version status unknown";
    annotations.push(`::${severity} title=${escapeProperty(title)}::${escapeData(findingText(finding))}`);
  }
  for (const [stageName, stage] of Object.entries(result.stages)) {
    if (stage.status === "failed") {
      annotations.push(`::error title=${escapeProperty(`${titleCase(stageName)} stage failed`)}::${escapeData(stage.reason ?? "Stage failed")}`);
    }
  }
  return annotations;
}

function toSarifResult(finding: SecurityFinding, manifests: ManifestFiles): SarifResult {
  const ruleId = finding.kevEntry.cveId || undefined;
  return {
    ...(ruleId ? { ruleId } : {}),
    level: LEVEL[finding.versionStatus],
    message: { text: findingText(finding) },
    locations: [{ physicalLocation: { artifactLocation: { uri: manifestFor(finding, manifests) } } }],
  };
}

function manifestFor(finding: SecurityFinding, manifests: ManifestFiles): string {
  const type = finding.component.ecosystem ?? (finding.component.purl ? parsePurl(finding.component.purl)?.type : undefined);
  // Fall back to any known manifest, then the repository root, so a result is never dropped.
  return (type ? manifests[type] : undefined) ?? Object.values(manifests).find(Boolean) ?? ".";
}

function findingText(finding: SecurityFinding): string {
  const fix = finding.versionStatus === "affected" && finding.patchedVersion ? `; fixed in ${finding.patchedVersion}` : "";
  return `${componentName(finding)}@${finding.component.version ?? "unknown"} is ${finding.versionStatus.replace("_", " ")}${fix}: ${advisoryText(finding)}`;
}

function advisoryText(finding: SecurityFinding): string {
  const ids = [finding.kevEntry.cveId, ...finding.advisoryIds.filter((id) => id !== finding.kevEntry.cveId)].filter(Boolean);
  const label = ids.length > 0 ? ids.join(", ") : "KEV entry without CVE";
  return `${label} (${finding.kevEntry.vendorProject} ${finding.kevEntry.product}: ${finding.kevEntry.vulnerabilityName})`;
}

function componentName(finding: SecurityFinding): string {
  return `${finding.component.namespace ? `${finding.component.namespace}/` : ""}${finding.component.name}`;
}

const URGENCY: Record<VersionStatus, number> = { affected: 0, unknown: 1, not_affected: 2 };
function sortByUrgency(findings: SecurityFinding[]): SecurityFinding[] {
  return [...findings].sort((a, b) => URGENCY[a.versionStatus] - URGENCY[b.versionStatus]);
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

/**
 * Renders an untrusted value (from lockfiles, KEV or OSV) as literal text in a
 * Markdown table cell: no links or images (`[x](url)`), emphasis, code,
 * headings, table breaks or HTML. CommonMark shows backslash-escaped
 * punctuation as-is, so ordinary text still reads normally.
 */
function markdownText(value: string): string {
  return value
    .replace(/\r?\n/g, " ")
    .replace(/[\\`*_[\]()#|~!]/g, "\\$&")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

/** Workflow-command message data: a raw newline would start a new (injected) command. */
function escapeData(value: string): string {
  return value.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}

/** Workflow-command property values (title=...) additionally reserve ":" and ",". */
function escapeProperty(value: string): string {
  return escapeData(value).replace(/:/g, "%3A").replace(/,/g, "%2C");
}

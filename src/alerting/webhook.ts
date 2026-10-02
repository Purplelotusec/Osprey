import type { CrossCheckMatch } from "../correlation/matcher.js";
import type { SecurityFinding, VersionStatus } from "../vulnerability/types.js";

export interface AlertOptions {
  webhookUrl: string;
  subjectName: string;
}

const MAX_LISTED = 10;

/** Alert sections in triage order: what needs action first. */
const SECTIONS: Array<{ status: VersionStatus; heading: (count: number) => string }> = [
  { status: "affected", heading: (n) => `:red_circle: *${n} affected* — installed version is vulnerable, act now` },
  { status: "unknown", heading: (n) => `:large_orange_circle: *${n} unknown* — couldn't tell if the installed version is affected, verify` },
  { status: "not_affected", heading: (n) => `:white_circle: *${n} patched* — has a KEV CVE but the installed version is not affected` },
];

/**
 * Sends one Slack-compatible message summarizing all findings from a single
 * run — not one message per finding, which would spam the channel on a bad
 * day and bury the signal. Every finding is an exact CVE match, so they are
 * grouped by whether the installed version is actually affected.
 */
export async function sendCrossCheckAlert(findings: SecurityFinding[], options: AlertOptions): Promise<void> {
  if (findings.length === 0) return;

  const lines: string[] = [`*Osprey — known exploited vulnerabilities: ${options.subjectName}*`];

  for (const { status, heading } of SECTIONS) {
    const group = findings.filter((finding) => finding.versionStatus === status);
    if (group.length === 0) continue;
    lines.push("", heading(group.length));
    for (const finding of group.slice(0, MAX_LISTED)) {
      lines.push(`• \`${componentLabel(finding)}\` — ${finding.kevEntry.cveId}: ${finding.kevEntry.vulnerabilityName}`);
    }
    if (group.length > MAX_LISTED) lines.push(`• …and ${group.length - MAX_LISTED} more`);
  }

  const res = await fetch(options.webhookUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text: lines.join("\n") }),
  });

  if (!res.ok) {
    throw new Error(`Webhook alert failed: HTTP ${res.status} ${res.statusText}`);
  }
}

/** Plain-text console fallback for when no webhook is configured. */
export function printCrossCheckResults(matches: CrossCheckMatch[], subjectName: string): void {
  if (matches.length === 0) {
    console.log(`${subjectName}: no KEV matches found.`);
    return;
  }

  console.log(`${subjectName}: ${matches.length} match(es) found\n`);
  for (const m of matches) {
    console.log(`[KEV] ${m.kevEntry.cveId}  ${componentLabel(m)}  (${m.kevEntry.vulnerabilityName})`);
  }
}

function componentLabel({ component }: CrossCheckMatch): string {
  const name = component.namespace ? `${component.namespace}/${component.name}` : component.name;
  return component.version ? `${name}@${component.version}` : name;
}

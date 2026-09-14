import type { CrossCheckMatch } from "../correlation/matcher.js";
import { fetchText } from "../network/http.js";

export interface AlertOptions {
  webhookUrl: string;
  subjectName: string;
}

/**
 * Sends one Slack-compatible message summarizing all matches from a single
 * cross-check run — not one message per match, which would spam the
 * channel on a bad day and bury the signal. High-confidence matches are
 * called out separately from low-confidence ones so a human can triage at
 * a glance which need immediate attention vs. which need a second look.
 */
export async function sendCrossCheckAlert(matches: CrossCheckMatch[], options: AlertOptions): Promise<void> {
  if (matches.length === 0) return;
  validateWebhookUrl(options.webhookUrl);

  const high = matches.filter((m) => m.confidence === "high");
  const low = matches.filter((m) => m.confidence === "low");

  const lines: string[] = [`*CRA Guard — KEV cross-check: ${options.subjectName}*`];

  if (high.length > 0) {
    lines.push("", `:red_circle: *${high.length} high-confidence match(es)* — exact package match, review now`);
    for (const m of high.slice(0, 10)) {
      lines.push(
        `• \`${m.component.name}${m.component.version ? "@" + m.component.version : ""}\` — ${m.kevEntry.cveId}: ${m.kevEntry.vulnerabilityName}`
      );
    }
  }

  if (low.length > 0) {
    lines.push("", `:large_orange_circle: *${low.length} low-confidence lead(s)* — name match only, verify before acting`);
    for (const m of low.slice(0, 10)) {
      lines.push(
        `• \`${m.component.name}${m.component.version ? "@" + m.component.version : ""}\` — ${m.kevEntry.cveId}: ${m.kevEntry.vulnerabilityName}`
      );
    }
  }

  await fetchText(options.webhookUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text: lines.join("\n") }),
  });
}

function validateWebhookUrl(endpoint: string): void {
  let parsed: URL;
  try {
    parsed = new URL(endpoint);
  } catch {
    throw new Error("Webhook URL must be a valid URL");
  }
  if (parsed.username || parsed.password) throw new Error("Webhook URL must not contain embedded credentials");
  const loopback = parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1" || parsed.hostname === "::1";
  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && loopback)) {
    throw new Error("Webhook URL must use HTTPS (HTTP is allowed only for loopback local development)");
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
    const tag = m.confidence === "high" ? "[HIGH]" : "[low] ";
    console.log(
      `${tag} ${m.kevEntry.cveId}  ${m.component.name}${m.component.version ? "@" + m.component.version : ""}  (${m.kevEntry.vulnerabilityName})`
    );
  }
}

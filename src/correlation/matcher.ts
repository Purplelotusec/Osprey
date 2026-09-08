import { parsePurl } from "../sbom/purl.js";
import type { NormalizedComponent } from "../sbom/types.js";
import type { KevEntry } from "../vulnerability/types.js";

export type MatchConfidence = "high" | "low";

export interface CrossCheckMatch {
  component: NormalizedComponent;
  kevEntry: KevEntry;
  confidence: MatchConfidence;
  matchedOn: "purl_ecosystem_name" | "vendor_product_name";
}

/**
 * Confidence tiers matter downstream (see the awareness/clock discussion):
 *
 * - "high": the component's PURL ecosystem/name lines up closely with the
 *   KEV entry's vendor/product AND the component identity came from a real
 *   package manager (PURL present) — as close to "this exact thing is
 *   shipped" as free-text KEV data allows.
 * - "low": only a loose vendor/product name match, no PURL corroboration —
 *   treat this as a lead a human should look at, not a confirmed hit.
 *
 * CISA KEV entries carry a CVE plus free-text vendor/product names, not a
 * machine-precise CPE/version range — so even "high" here is not the same
 * guarantee an exact CPE-range match from NVD would give. Upgrading to an
 * NVD/OSV-backed provider with real affected-version ranges is the natural
 * next step once this proves out.
 */
export function crossCheck(components: NormalizedComponent[], kevEntries: KevEntry[]): CrossCheckMatch[] {
  const matches: CrossCheckMatch[] = [];

  for (const component of components) {
    for (const entry of kevEntries) {
      const match = evaluateMatch(component, entry);
      if (match) matches.push(match);
    }
  }

  return matches;
}

function evaluateMatch(component: NormalizedComponent, entry: KevEntry): CrossCheckMatch | null {
  const componentName = component.name.toLowerCase();
  const productName = entry.product.toLowerCase();
  const vendorName = entry.vendorProject.toLowerCase();

  const nameMatchesProduct = componentName === productName;
  const nameMatchesVendor = component.vendor?.toLowerCase() === vendorName;

  if (!nameMatchesProduct && !nameMatchesVendor) return null;

  // "High" confidence requires a PURL-backed identity (came from an actual
  // lockfile, not guesswork) AND the exact product-name match, not just
  // the looser vendor match.
  const confidence: MatchConfidence = component.purl && nameMatchesProduct ? "high" : "low";

  return {
    component,
    kevEntry: entry,
    confidence,
    matchedOn: component.purl && nameMatchesProduct ? "purl_ecosystem_name" : "vendor_product_name",
  };
}

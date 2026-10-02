import type { NormalizedComponent } from "../sbom/types.js";
import type { KevEntry } from "../vulnerability/types.js";
import { osvPackage, osvPackageKey, type OsvAdvisory } from "../vulnerability/osv.js";

/**
 * Every match is an exact CVE link from OSV, so confidence is always "high".
 * The field (and SboimResult.lowConfidenceMatchCount, always 0) stays in the
 * schemaVersion 1.0 output for consumers written against the old name-based
 * matcher, which also produced "low" matches.
 */
export type MatchConfidence = "high";

export interface CrossCheckMatch {
  component: NormalizedComponent;
  kevEntry: KevEntry;
  confidence: MatchConfidence;
  matchedOn: "cve_from_osv";
}

/**
 * CVE-based cross-checking strategy:
 *
 * We NO LONGER match by fuzzy name comparison (too many false positives).
 * Instead, we:
 * 1. Query OSV for vulnerabilities in each package
 * 2. Extract CVE IDs from OSV advisories
 * 3. Check if those CVE IDs appear in CISA KEV
 * 4. Only report packages where OSV CVE = KEV CVE (actively exploited)
 *
 * This ensures we only flag packages with CONFIRMED vulnerabilities that
 * are ACTUALLY being exploited in the wild according to CISA.
 */
export function crossCheckWithAdvisories(
  components: NormalizedComponent[],
  kevEntries: KevEntry[],
  advisoriesByPackage: Map<string, OsvAdvisory[]>
): CrossCheckMatch[] {
  const matches: CrossCheckMatch[] = [];
  const kevCveMap = new Map<string, KevEntry>();

  // Index KEV entries by CVE ID for fast lookup
  for (const entry of kevEntries) {
    kevCveMap.set(entry.cveId.toUpperCase(), entry);
  }

  // For each component, check if its OSV vulnerabilities appear in KEV
  for (const component of components) {
    const pkg = osvPackage(component);
    if (!pkg) continue;

    const advisories = advisoriesByPackage.get(osvPackageKey(pkg)) ?? [];
    // Several advisories (e.g. GHSA-… and PYSEC-…) often alias the same CVE;
    // report each (component, CVE) once. Enrichment still cites every advisory.
    const matchedCves = new Set<string>();

    for (const advisory of advisories) {
      // Check if this advisory's CVE is in CISA KEV
      const cveIds = extractCveIds(advisory);

      for (const cveId of cveIds) {
        const normalizedCve = cveId.toUpperCase();
        const kevEntry = kevCveMap.get(normalizedCve);
        if (kevEntry && !matchedCves.has(normalizedCve)) {
          matchedCves.add(normalizedCve);
          // This CVE is actively exploited!
          matches.push({
            component,
            kevEntry,
            confidence: "high", // High confidence because it's based on exact CVE match
            matchedOn: "cve_from_osv",
          });
        }
      }
    }
  }

  return matches;
}

function extractCveIds(advisory: OsvAdvisory): string[] {
  const cves: string[] = [];

  // Check advisory ID itself
  if (advisory.id.startsWith("CVE-")) {
    cves.push(advisory.id);
  }

  // Check aliases
  for (const alias of advisory.aliases ?? []) {
    if (alias.startsWith("CVE-")) {
      cves.push(alias);
    }
  }

  return cves;
}

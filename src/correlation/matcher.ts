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
 * Reports each component whose OSV advisories name a CVE that is in CISA KEV.
 *
 * Matching is by CVE ID only. KEV identifies software by free-text vendor and
 * product names, which don't map reliably onto package names, so name matching
 * is deliberately not attempted: a package is linked to a KEV entry only through
 * an OSV advisory for that exact package.
 */
export function crossCheckWithAdvisories(
  components: NormalizedComponent[],
  kevEntries: KevEntry[],
  advisoriesByPackage: Map<string, OsvAdvisory[]>
): CrossCheckMatch[] {
  const kevByCve = new Map(kevEntries.map((entry) => [entry.cveId.toUpperCase(), entry]));
  const matches: CrossCheckMatch[] = [];

  for (const component of components) {
    const pkg = osvPackage(component);
    if (!pkg) continue;

    // Several advisories (e.g. GHSA-… and PYSEC-…) often alias the same CVE;
    // report each (component, CVE) once. Enrichment still cites every advisory.
    const matchedCves = new Set<string>();

    for (const advisory of advisoriesByPackage.get(osvPackageKey(pkg)) ?? []) {
      for (const cveId of cveIdsOf(advisory)) {
        const kevEntry = kevByCve.get(cveId);
        if (!kevEntry || matchedCves.has(cveId)) continue;
        matchedCves.add(cveId);
        matches.push({ component, kevEntry, confidence: "high", matchedOn: "cve_from_osv" });
      }
    }
  }

  return matches;
}

/** The CVE IDs an advisory refers to: its own ID (for CVE-sourced advisories) and its aliases. */
function cveIdsOf(advisory: OsvAdvisory): string[] {
  return [advisory.id, ...(advisory.aliases ?? [])]
    .filter((id) => id.startsWith("CVE-"))
    .map((id) => id.toUpperCase());
}

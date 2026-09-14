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
  const parsedPurl = component.purl ? parsePurl(component.purl) : null;

  const nameMatchesProduct = componentName === productName;
  const nameMatchesVendor = component.vendor?.toLowerCase() === vendorName;

  if (!nameMatchesProduct && !nameMatchesVendor) return null;

  // A scoped npm package such as @aws-sdk/core is not identified by "core"
  // alone. Reject generic scoped-name matches unless the KEV vendor also
  // identifies the package namespace, rather than turning them into false
  // positives for products such as WordPress Core.
  if (
    nameMatchesProduct &&
    parsedPurl?.type === "npm" &&
    parsedPurl.namespace &&
    isGenericPackageName(componentName) &&
    !namespaceMatchesVendor(parsedPurl.namespace, vendorName)
  ) {
    return null;
  }

  // "High" confidence requires a PURL-backed identity (came from an actual
  // lockfile, not guesswork), the exact product-name match, and a package
  // identity strong enough to distinguish scoped generic names.
  const strongPackageIdentity =
    Boolean(component.purl) &&
    nameMatchesProduct &&
    (!parsedPurl || !isGenericPackageName(componentName) || !parsedPurl.namespace || namespaceMatchesVendor(parsedPurl.namespace, vendorName));
  const confidence: MatchConfidence = strongPackageIdentity ? "high" : "low";

  return {
    component,
    kevEntry: entry,
    confidence,
    matchedOn: strongPackageIdentity ? "purl_ecosystem_name" : "vendor_product_name",
  };
}

function isGenericPackageName(name: string): boolean {
  return new Set(["core"]).has(name);
}

function namespaceMatchesVendor(namespace: string, vendor: string): boolean {
  const normalizedNamespace = namespace.replace(/^@/, "").toLowerCase();
  return vendor.includes(normalizedNamespace) || normalizedNamespace.includes(vendor);
}

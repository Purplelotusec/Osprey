/**
 * Minimal Package URL (PURL) builder/parser, per the purl-spec:
 *   pkg:type/namespace/name@version?qualifiers#subpath
 * Hand-rolled rather than pulling in a dependency — the spec is small and
 * stable, and this keeps component-identity logic auditable in one place.
 */
export interface ParsedPurl {
  type: string;
  namespace?: string;
  name: string;
  version?: string;
}

export function buildPurl(p: ParsedPurl): string {
  const ns = p.namespace ? `${encodeURIComponent(p.namespace)}/` : "";
  const version = p.version ? `@${encodeURIComponent(p.version)}` : "";
  return `pkg:${p.type}/${ns}${encodeURIComponent(p.name)}${version}`;
}

export function parsePurl(purl: string): ParsedPurl | null {
  if (!purl.startsWith("pkg:")) return null;
  try {
    let rest = purl.slice(4);
    const qIdx = rest.indexOf("?");
    if (qIdx !== -1) rest = rest.slice(0, qIdx);
    const hIdx = rest.indexOf("#");
    if (hIdx !== -1) rest = rest.slice(0, hIdx);

    const atIdx = rest.lastIndexOf("@");
    const version = atIdx !== -1 ? decodeURIComponent(rest.slice(atIdx + 1)) : undefined;
    const typeAndRest = atIdx !== -1 ? rest.slice(0, atIdx) : rest;

    const segments = typeAndRest.split("/").filter(Boolean);
    if (segments.length < 2) return null;

    const type = segments[0].toLowerCase();
    const name = decodeURIComponent(segments[segments.length - 1]);
    const namespace = segments.length > 2
      ? segments.slice(1, -1).map(decodeURIComponent).join("/")
      : undefined;

    return { type, namespace, name, version };
  } catch {
    return null;
  }
}

export function canonicalPurl(purl: string): string | null {
  const parsed = parsePurl(purl);
  return parsed ? buildPurl(parsed) : null;
}

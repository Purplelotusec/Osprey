import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { buildPurl } from "../purl.js";
import type { NormalizedComponent } from "../types.js";
import { parseStringPromise } from "xml2js";

export interface MavenGenerationResult {
  subjectName: string;
  subjectVersion?: string;
  components: NormalizedComponent[];
  sourceFile: string;
}

/**
 * Generates SBOM from Maven project by parsing pom.xml
 * Note: This is a basic implementation that reads direct dependencies from pom.xml
 * For a complete dependency tree with transitive dependencies, use `mvn dependency:tree` or similar tools
 */
export async function generateFromMavenProject(projectDir: string): Promise<MavenGenerationResult> {
  const pomPath = join(projectDir, "pom.xml");
  if (!existsSync(pomPath)) {
    throw new Error(`No pom.xml found at ${pomPath}`);
  }

  const pomContent = readFileSync(pomPath, "utf-8");
  const pom = await parseStringPromise(pomContent);

  const project = pom.project;
  const subjectName = project.artifactId?.[0] ?? "unknown-maven-project";
  const subjectVersion = project.version?.[0];

  const components: NormalizedComponent[] = [];

  // Parse dependencies
  const dependencies = project.dependencies?.[0]?.dependency ?? [];
  for (const dep of dependencies) {
    const groupId = dep.groupId?.[0];
    const artifactId = dep.artifactId?.[0];
    const version = dep.version?.[0];

    if (!groupId || !artifactId || !version) continue;

    // Skip version properties (e.g., ${spring.version}) - we can't resolve these without Maven
    if (version.includes("${")) continue;

    components.push({
      purl: buildPurl({ type: "maven", namespace: groupId, name: artifactId, version }),
      ecosystem: "maven",
      namespace: groupId,
      name: artifactId,
      version,
      isDirect: true,
    });
  }

  return {
    subjectName,
    subjectVersion,
    components,
    sourceFile: "pom.xml",
  };
}

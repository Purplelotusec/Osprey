import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { buildPurl } from "../purl.js";
import type { NormalizedComponent } from "../types.js";

export interface RubyGemsGenerationResult {
  subjectName: string;
  subjectVersion?: string;
  components: NormalizedComponent[];
  sourceFile: string;
}

/**
 * Generates SBOM from Ruby project by parsing Gemfile.lock
 * This parser handles the basic Gemfile.lock format
 */
export function generateFromRubyGemsProject(projectDir: string): RubyGemsGenerationResult {
  const lockPath = join(projectDir, "Gemfile.lock");
  if (!existsSync(lockPath)) {
    throw new Error(`No Gemfile.lock found at ${lockPath}. Please run 'bundle install' to generate it.`);
  }

  const lockContent = readFileSync(lockPath, "utf-8");
  const components: NormalizedComponent[] = [];

  // Parse Gemfile.lock format
  // GEM
  //   remote: https://rubygems.org/
  //   specs:
  //     package-name (1.2.3)
  //       dependency (>= 1.0)

  let inGemSection = false;
  let inSpecsSection = false;

  for (const line of lockContent.split("\n")) {
    if (line.trim() === "GEM") {
      inGemSection = true;
      inSpecsSection = false;
      continue;
    }

    if (inGemSection && line.trim() === "specs:") {
      inSpecsSection = true;
      continue;
    }

    if (line.trim() === "PLATFORMS" || line.trim() === "DEPENDENCIES" || line.trim() === "BUNDLED WITH") {
      inGemSection = false;
      inSpecsSection = false;
      continue;
    }

    if (inSpecsSection && line.match(/^    \w/)) {
      // This is a gem entry like "    package-name (1.2.3)"
      const match = line.trim().match(/^([a-zA-Z0-9_-]+)\s+\(([^)]+)\)/);
      if (match) {
        const [, name, version] = match;

        components.push({
          purl: buildPurl({ type: "gem", name, version }),
          ecosystem: "rubygems",
          name,
          version,
          isDirect: false, // Gemfile.lock doesn't easily distinguish direct vs transitive
        });
      }
    }
  }

  return {
    subjectName: projectDir.split("/").filter(Boolean).pop() ?? "unknown-ruby-project",
    components,
    sourceFile: "Gemfile.lock",
  };
}

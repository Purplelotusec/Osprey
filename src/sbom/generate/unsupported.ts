import type { Ecosystem } from "./index.js";

/** An ecosystem Osprey can't generate an SBOM for, recognised by the files at a project's root. */
interface UnsupportedEcosystem {
  label: string;
  /** Exact file names, or patterns for files named after the project (e.g. App.csproj). */
  files: Array<string | RegExp>;
  /** Not reported when this ecosystem was audited (e.g. a Gradle build with lockfiles). */
  coveredBy?: Ecosystem;
  /** Why it wasn't audited; defaults to "Osprey does not read <label> projects". */
  reason?: string;
  /** How to audit it anyway. */
  hint: string;
}

const SBOM_HINT = "Generate a CycloneDX SBOM for it and check that with cra-kev --sbom to include them.";

/** Lockfiles first, so the warning names the file that actually pins the versions. */
export const UNSUPPORTED_ECOSYSTEMS: UnsupportedEcosystem[] = [
  {
    label: "Rust",
    files: ["Cargo.toml"],
    coveredBy: "cargo",
    reason: "there is no Cargo.lock to read exact versions from",
    hint: "Commit the Cargo.lock that cargo generate-lockfile writes to include them.",
  },
  { label: "Go", files: ["go.sum", "go.mod"], hint: SBOM_HINT },
  { label: "Ruby", files: ["Gemfile.lock", "Gemfile"], hint: SBOM_HINT },
  { label: "PHP", files: ["composer.lock", "composer.json"], hint: SBOM_HINT },
  { label: ".NET", files: ["packages.lock.json", "Directory.Packages.props", "packages.config", /\.(cs|fs|vb)proj$/, /\.sln$/], hint: SBOM_HINT },
  { label: "Swift", files: ["Package.resolved", "Package.swift"], hint: SBOM_HINT },
  { label: "Dart", files: ["pubspec.lock", "pubspec.yaml"], hint: SBOM_HINT },
  { label: "Elixir", files: ["mix.lock", "mix.exs"], hint: SBOM_HINT },
  {
    label: "Java (Maven)",
    files: ["pom.xml"],
    coveredBy: "maven",
    reason: "Osprey does not resolve pom.xml dependencies",
    hint: "Generate a CycloneDX SBOM (mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom) and check it with cra-kev --sbom to include them.",
  },
  {
    label: "Java (Gradle)",
    files: ["build.gradle.kts", "build.gradle"],
    coveredBy: "maven",
    reason: "the build has no gradle.lockfile to read exact versions from",
    hint: "Enable Gradle dependency locking and commit the gradle.lockfile it writes (gradle dependencies --write-locks), or check a CycloneDX SBOM with cra-kev --sbom.",
  },
];

/** Each unsupported ecosystem present among `fileNames`, with the first file that identified it. */
export function findUnsupportedEcosystems(fileNames: string[], audited: Ecosystem[] = []): Array<{ ecosystem: UnsupportedEcosystem; file: string }> {
  const found: Array<{ ecosystem: UnsupportedEcosystem; file: string }> = [];
  for (const ecosystem of UNSUPPORTED_ECOSYSTEMS) {
    if (ecosystem.coveredBy && audited.includes(ecosystem.coveredBy)) continue;
    for (const pattern of ecosystem.files) {
      const file = typeof pattern === "string" ? fileNames.find((name) => name === pattern) : fileNames.filter((name) => pattern.test(name)).sort()[0];
      if (file) {
        found.push({ ecosystem, file });
        break;
      }
    }
  }
  return found;
}

/** One warning per unsupported ecosystem: a passing audit must not read as covering code it never checked. */
export function unsupportedEcosystemWarnings(fileNames: string[], audited: Ecosystem[]): string[] {
  return findUnsupportedEcosystems(fileNames, audited).map(
    ({ ecosystem, file }) => `Found ${file}: its ${ecosystem.label} dependencies were NOT audited — ${reasonFor(ecosystem)}. ${ecosystem.hint}`
  );
}

function reasonFor(ecosystem: UnsupportedEcosystem): string {
  return ecosystem.reason ?? `Osprey does not read ${ecosystem.label} projects`;
}

/** E.g. "Found go.mod (Go), but Osprey does not read Go projects.", for errors when nothing supported was found. */
export function describeUnsupportedEcosystems(fileNames: string[]): string | undefined {
  const found = findUnsupportedEcosystems(fileNames);
  return found.length > 0 ? found.map(({ ecosystem, file }) => `Found ${file} (${ecosystem.label}), but ${reasonFor(ecosystem)}.`).join(" ") : undefined;
}

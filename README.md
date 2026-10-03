#  Osprey

<img width="1024" height="309" alt="image" src="https://github.com/user-attachments/assets/87cfc0e3-2984-478a-814e-64ac755f515a" />




https://www.purplelotus.space/blog/introducing-osprey

<img width="753" height="181" alt="image" src="https://github.com/user-attachments/assets/7cba3dda-a61a-42b0-b61e-cbabd8689dac" />


Osprey is a CLI (`cra`) that builds a Software Bill of Materials (SBOM) from your project, cross-checks every component against the [CISA Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog, and tells you which dependencies are *actively exploited in the wild*, not merely "have a CVE".

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [CLI Reference](#cli-reference)
- [Understanding the Output](#understanding-the-output)
- [Structured Results & CI](#structured-results--ci)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Development](#development)
- [Supported Ecosystems & Limitations](#supported-ecosystems--limitations)
- [Security Notes](#security-notes)

---

## Features

| | |
|---|---|
|  **KEV detection** | Cross-checks components against CISA's KEV catalog |
|  **Exact CVE matching** | Links each package to its CVEs through OSV advisories. No name guessing, so no "WordPress Core" false positives |
|  **Version intelligence** | Uses [OSV](https://osv.dev) to decide whether your *installed* version is actually affected, comparing versions with each ecosystem's own rules |
|  **Ecosystems** | npm and Python lockfiles, plus Java (Maven/Gradle) and any CycloneDX SBOM |
|  **Remote auditing** | Audit a GitHub repo without cloning it |
| **SBOM signing** | Ed25519 signatures in a DSSE envelope, with tamper detection |


---

## Quick Start

```bash
git clone https://github.com/Purplelotusec/Osprey
cd osprey
npm install      # builds automatically via the "prepare" script
npm link         # optional: installs cra, cra-audit, cra-sbom, cra-kev, cra-report globally
```

Audit a project:

```bash
cra --path /path/to/your/project
```

Audit a GitHub repository:

```bash
cra --url facebook/react
```

Without a global install, prefix commands with `npm run` and separate flags with `--`:

```bash
npm run cra -- --path . --verbose
```

> The `--` separates npm's own flags from the tool's flags; everything after it is passed to Osprey.

---

## Usage

### Audit a local project

```bash
cra --path .
cra --path . --verbose       # extra detail
cra --path . --summary       # condensed output
```

### Audit a GitHub repository

```bash
cra --url https://github.com/owner/repo
cra --url owner/repo                       # short form
cra --url owner/repo/tree/main/packages/x  # branch and subdirectory
```

Private repositories need a token:

```bash
export GITHUB_TOKEN=YOUR_TOKEN
cra --url owner/private-repo
# or: cra --url owner/private-repo --github-token YOUR_TOKEN
```

### Use in CI

```bash
cra --path . --fail-on-high --output results.json
```

Exits non-zero if any dependency's **installed version is affected** by a known exploited vulnerability. A package that has a KEV CVE but is already patched does not fail the build.

### Generate and sign an SBOM

```bash
cra-sbom --path . --output sbom.json --sign --generate-key
```

### Check an existing SBOM

```bash
cra-kev --sbom sbom.json --cache ~/.osprey/kev-cache.json
cra-kev --sbom sbom.json --offline            # cached KEV and OSV data only, no network
```

Any CycloneDX JSON SBOM works. Components in ecosystems Osprey can't check (for example Cargo or Go), or without a version, are listed in a warning as **not covered**, and the report says "M of N packages checked". If none of an SBOM's components can be checked, the audit fails instead of passing.

### Audit a Java (Maven / Gradle) project

Maven has no lockfile, and only the build tool can resolve the real dependency tree (parent POMs, BOMs, properties, version mediation). Let the build produce a CycloneDX SBOM, then check it:

```bash
# Maven
mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom -DoutputFormat=json
cra-kev --sbom target/bom.json --fail-on-high

# Gradle (org.cyclonedx.bom plugin; the output path depends on the plugin version and config)
gradle cyclonedxBom
cra-kev --sbom build/reports/bom.json --fail-on-high
```

Maven versions are compared using Maven's own ordering rules (`2.0-beta9 < 2.0`, `1-rc1 == 1-cr1`, `9.0.0.M1 == 9.0.0-M1`), so OSV's affected ranges are evaluated exactly as Maven orders versions. Findings tell you which version to set in `pom.xml` (or the BOM that manages it). Osprey never runs Maven or Gradle itself: building executes plugins and build scripts, which isn't safe for code you're auditing.

### Alert via webhook

```bash
cra-kev --path . --webhook https://hooks.slack.com/services/... --fail-on-high
```

---

## CLI Reference

| Command | Purpose |
|---|---|
| `cra` | Main audit command (alias for `cra-audit`) |
| `cra-audit` | Full audit: generate SBOM → poll KEV → cross-check → report |
| `cra-sbom` | Generate (and optionally sign) an SBOM |
| `cra-kev` | Check an existing SBOM or project against KEV |
| `cra-report` | Produce GitHub Actions reports (job summary, annotations, SARIF) |

### `cra` / `cra-audit` options

| Option | Description | Default |
|---|---|---|
| `-p, --path <dir>` | Local project directory to audit | `.` |
| `-u, --url <github-url>` | GitHub repository to audit | – |
| `--cache <file>` | KEV cache file path | `~/.osprey/kev-cache.json` |
| `--osv-cache <file>` | OSV advisory cache file path | `~/.osprey/osv-cache.json` |
| `--offline` | Use only cached KEV and OSV data, with no vulnerability-data requests. Fails if any package isn't cached | `false` |
| `--output <file>` | Write detailed JSON result to file | – |
| `--verbose` | Show detailed output | `false` |
| `--fail-on-high` | Exit with error if an installed version is affected by a KEV CVE | `false` |
| `--github-token <token>` | GitHub token for private repos | `$GITHUB_TOKEN` |
| `--summary` | Show only the summary | `false` |

**Accepted GitHub URL formats**

- `https://github.com/owner/repo`
- `github.com/owner/repo`
- `owner/repo`
- `https://github.com/owner/repo/tree/branch`
- `owner/repo/tree/branch/path/to/dir`

---

## Understanding the Output

| Symbol | Meaning |
|---|---|
| ✓ **Green** | No actively exploited vulnerabilities detected |
| ✗ **Red** | Actively exploited vulnerable components found |
| ⚠ **Yellow** | Warnings, or findings whose version status is unknown |

**Clean run**

```
Auditing: vacanza/holidays

Analyzing repository...
Ecosystems: python (105)
Checking for vulnerabilities...

✓ No active exploitable vulnerabilities detected
```

**Findings**

```
Vulnerability Audit
───────────────────
1281 packages checked
✗ 1 vulnerable package(s)
✓ 1 safe (patched)

Known Exploited Vulnerabilities
───────────────────────────────

1. CVE-2024-12345
   Component: vulnerable-package@1.2.3
   PURL: pkg:npm/vulnerable-package@1.2.3
   Vulnerability: Remote Code Execution in vulnerable-package
   Version Status: AFFECTED (1.2.3 is vulnerable)
   Required Action: Apply mitigations per vendor instructions or discontinue use
   ⚠ REMEDIATION:
   Current: 1.2.3 → Upgrade to: 1.2.4+
   Run: npm install vulnerable-package@1.2.4
```

### How matching works

Osprey never matches on names. KEV's free-text vendor and product fields produced false positives that way (for example `@aws-sdk/core` matching "WordPress Core"). Instead, each dependency is looked up in [OSV](https://osv.dev), the CVE IDs from its advisories are collected, and only the CVEs that appear in KEV are reported. Every finding is therefore an exact CVE link for that exact package.

### Version status

For npm, Python (PyPI) and Maven packages, OSV advisories determine whether your installed version is affected. Each ecosystem's versions are compared with its own rules: semver for npm, PEP 440 for PyPI (`1.0rc1 < 1.0`, `1.0 == 1.0.0`), and Maven's version ordering for Maven. Advisories that cover several version windows are evaluated window by window, and the suggested fix is always the next fixed version above yours, never a downgrade.

| `versionStatus` | Meaning |
|---|---|
| `affected` | OSV evidence covers the installed version |
| `not_affected` | Available evidence excludes the installed version |
| `unknown` | Version or advisory evidence couldn't be established. **Never treated as affected.** |

`exploitationStatus: "known_exploited"` is independent: it comes from CISA KEV, not OSV.

---

## Structured Results & CI

`--output` (on `cra`) or `--result` (on `cra-kev`) writes a versioned JSON result for CI systems and downstream automation:

```bash
cra-kev --sbom sbom.json --result result.json --fail-on-high
```

The result (`schemaVersion: "1.0"`) includes:

- SBOM component count
- KEV snapshot metadata
- Full match details
- Warnings and errors
- A `status` (and optional `reason`) for each pipeline stage

Version-enriched findings add `identityConfidence`, `versionStatus`, `exploitationStatus`, and `advisoryIds`. Signing and storage stages currently report `skipped` until secure CI credentials and key management are configured. Consumers that only read `status` remain compatible.

### GitHub Actions reporting (`cra-report`)

`cra-report` turns a result file into three outputs:
- a Markdown job summary, appended to `$GITHUB_STEP_SUMMARY` automatically
- workflow annotations
- SARIF 2.1.0 for GitHub code scanning

```bash
cra-report --result result.json --sarif osprey.sarif --annotations
```

| Option | Description |
|---|---|
| `--result <file>` | Result JSON from `cra --output` or `cra-kev --result` (required, validated before rendering) |
| `--summary <file>` | Also write the Markdown summary to a file |
| `--sarif <file>` | Write SARIF for code scanning |
| `--annotations` | Print workflow annotations |
| `--project <dir>` | Audited directory (default `.`), used to attach SARIF findings to its dependency files |

How each finding is reported depends on whether the installed version is affected:

| Version status | SARIF level | Annotation |
|---|---|---|
| `affected` | `error` | error |
| `unknown` | `warning` | warning |
| `not_affected` (patched) | `note` | none |

Each SARIF finding is attached to the dependency file its package came from (`package-lock.json`, `uv.lock`, …), and each CVE becomes a rule carrying the KEV description and CISA's required action. The summary reports FAILED whenever an installed version is affected, even if `--fail-on-high` wasn't set, and never presents an incomplete audit as clean. Values from lockfiles and KEV are escaped so they can't inject Markdown, HTML or workflow commands.

```yaml
- run: npx cra --path . --output osprey-result.json --fail-on-high
- if: always()
  run: npx cra-report --result osprey-result.json --sarif osprey.sarif --annotations
- if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: osprey.sarif
```


---

## Development

```bash
npm install     # also builds
npm test        # runs the test suite
```

The tests cover npm/Python SBOM generation, signing round-trips, tamper detection, wrong-key rejection, CVE-based matching, npm/PyPI OSV version evaluation, and reporting.

To remove global commands installed with `npm link`:

```bash
npm unlink -g <package-name>
```

Runtime dependencies are intentionally minimal: `commander`, `zod`, `semver`, `smol-toml` (zero-dependency TOML parser for Python lockfiles), and `@aws-sdk/client-s3`.

---

## Supported Ecosystems 

### What works today

- **npm:** full `package-lock.json` (v1, v2, v3) parsing, including direct vs. transitive dependencies, scoped packages, and deduplication.
- **Python:** every major lockfile format, detected in this order of preference:

  | File | Tool | Direct dependencies from |
  |---|---|---|
  | `uv.lock` | uv | the workspace member's dependencies, extras and dev groups |
  | `poetry.lock` | Poetry | `pyproject.toml` |
  | `pdm.lock` | PDM | `pyproject.toml` |
  | `pylock.toml`, `pylock.<name>.toml` | PEP 751 standard (pip, uv, PDM, Pipenv); named variants are merged | `pyproject.toml` |
  | `Pipfile.lock` | Pipenv (`default` and `develop`) | `Pipfile` |
  | `requirements.lock`, `requirements-dev.lock` | Rye (read together) | `pyproject.toml` |
  | `requirements.txt` | pip, pip-compile, `uv export`, `pip freeze` | `pyproject.toml`, otherwise every pin |

  Every package is recorded at its exact resolved version, transitive dependencies included. `pyproject.toml` covers `[project]`, `[dependency-groups]`, `[tool.poetry]`, and the PDM, uv and Rye dev-dependency tables. If no source of direct dependencies is available, directness is left unknown rather than guessed.

  `requirements.txt` handling follows pip's syntax: `-r` includes are followed (with cycle protection), `-c` constraint files are not (they install nothing), and hashes, `\` continuations, extras (`pkg[extra]==`), environment markers and `===` pins are understood. Ranges, wildcards (`==4.*`), direct URL references and editable installs have no exact index version, so they are skipped and reported, never guessed.

  Git, URL and local-path packages in any lockfile are skipped and reported as warnings, because they aren't the PyPI release a `pkg:pypi` PURL would claim. The project's own entry (an editable install of itself) is excluded silently.
- **Mixed projects:** every ecosystem present is audited into one SBOM. A Django or Flask backend with an npm-built frontend gets both its Python and npm dependencies checked, and `cra` prints the coverage (`Ecosystems: npm (989), python (292)`). Use `cra-sbom --ecosystem npm|python` to restrict the SBOM to one.
- **Remote auditing (`--url`):** reads the repository's default branch unless a `/tree/<branch>` is given. It fetches the preferred manifest of each ecosystem: `package-lock.json` for npm, and the Python files above in the same order. `package.json` is used only when no other manifest exists, since it holds ranges and in a Python repo is often just front-end tooling. It also fetches the companion files: `pyproject.toml`, `Pipfile`, `requirements-dev.lock`, and `-r` includes (only within the audited directory, at most 25 files).
- **Signing:** Ed25519 over DSSE pre-authentication encoding. Changing one byte of a signed SBOM, or verifying with the wrong key, fails verification.
- **KEV polling:** Zod schema validation plus local caching, so a network failure can't silently report "no vulnerabilities". An empty feed counts as a failure. The cache is written atomically and validated when read, so a truncated, edited or foreign cache file fails the run with a clear message instead of shrinking what gets checked.
- **OSV lookups:** OSV is the only link from a package to its CVEs. Results are cached in `~/.osprey/osv-cache.json`, written atomically and validated the same way as the KEV cache. Online runs always fetch fresh data. If OSV is unreachable, the cache is used, with a warning, but only when it covers every package. Otherwise the audit fails ("Audit incomplete", exit code 1) rather than passing with packages unchecked. `--offline` reads only the cache, under the same rule. Whenever cached data is used, the report says how old it is.

### Known limitations

- **Lockfile coverage:** no `yarn.lock`, `pnpm-lock.yaml`, `go.sum`, or `Cargo.lock` support yet. Conda environments (`conda-lock.yml`, `pixi.lock`) aren't read, since they lock conda packages rather than PyPI releases. `pyproject.toml` alone (without a lockfile) isn't used for versions, since it only declares ranges.
- **Remote named PEP 751 lockfiles:** `--url` only finds `pylock.toml`, because named variants (`pylock.dev.toml`) can't be discovered without listing the directory. Local audits read all of them.
- **Matching depends on OSV:** a KEV CVE is found only when an OSV advisory links it to the package. KEV entries for software that isn't distributed as an npm, PyPI or Maven package (operating systems, appliances) can't match, which is expected.
- **Java dependency resolution:** Osprey reads Java dependencies from a build-generated CycloneDX SBOM, not from `pom.xml`. Libraries shaded or bundled inside other JARs don't appear in the dependency tree, so they aren't covered.
- **Local-key signing:** Ed25519 with local keys, not Sigstore keyless or a transparency log. The envelope shape stays the same if you upgrade to cosign later.
- **KEV feed verification:** the poller was verified end-to-end against a synthetic snapshot matching the real response shape. Confirm behavior against the live CISA feed in your own environment.

---



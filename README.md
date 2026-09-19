# 🦅 Osprey

https://www.purplelotus.space/blog/introducing-osprey

**SBOM generation, signing, and CISA KEV vulnerability detection for your dependencies.**

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
| 🚨 **KEV detection** | Cross-checks components against CISA's KEV catalog |
| 🎯 **Confidence tiers** | `high` (PURL-backed exact match) vs `low` (name/vendor match only) |
| 🧠 **Version intelligence** | Uses [OSV](https://osv.dev) to decide whether your *installed* version is actually affected |
| 🌐 **Remote auditing** | Audit a GitHub repo without cloning it |
| 🔏 **SBOM signing** | Ed25519 signatures in a DSSE envelope, with tamper detection |
| 🔔 **Alerting** | Slack-compatible webhook, one batched message per run |

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

Exits non-zero if any **high-confidence** exploited vulnerability is found.

### Generate and sign an SBOM

```bash
cra-sbom --path . --output sbom.json --sign --generate-key
```

### Check an existing SBOM

```bash
cra-kev --sbom sbom.json --cache ~/.osprey/kev-cache.json
cra-kev --sbom sbom.json --offline            # cached KEV data only
```

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
| `--offline` | Use only cached KEV data (no network) | `false` |
| `--output <file>` | Write detailed JSON result to file | – |
| `--verbose` | Show detailed output | `false` |
| `--fail-on-high` | Exit with error on high-confidence matches | `false` |
| `--show-low` | Include low-confidence matches in output | `true` |
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
| ⚠ **Yellow** | Warnings or low-confidence matches |

**Clean run**

```
Auditing: /path/to/project

Generating SBOM from local project...
Found 245 components

Polling CISA Known Exploited Vulnerabilities (KEV)...
Loaded 1,234 KEV entries (as of 2026-09-18)

✓ No active exploitable vulnerabilities detected
All components are clear of known exploited vulnerabilities.
```

**Findings**

```
✗ Vulnerable components detected

  ✗ 2 HIGH confidence match(es)
  ⚠ 1 LOW confidence match(es)

1. CVE-2024-12345
   Component: vulnerable-package@1.2.3
   PURL: pkg:npm/vulnerable-package@1.2.3
   Vulnerability: Remote Code Execution in vulnerable-package
   Version Status: AFFECTED (1.2.3 is vulnerable)
   Required Action: Apply mitigations per vendor instructions or discontinue use
```

### Confidence tiers

CISA KEV entries use free-text vendor and product names, not machine-precise CPE ranges, so Osprey grades every match:

- **`high`**: PURL-backed exact product match.
- **`low`**: name/vendor match only.

> ⚠️ **Do not trigger automated regulatory or incident clocks on `low` confidence matches.** See `src/correlation/matcher.ts` for the reasoning.

### Version status

For npm packages, OSV advisories determine whether your installed version is affected:

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

The GitHub Actions reporter (`cra-report`) turns this result into a job summary, escaped annotations, and SARIF output.


---

## Development

```bash
npm install     # also builds
npm test        # runs the test suite (49 tests)
```

The tests cover npm/Python SBOM generation, signing round-trips, tamper detection, wrong-key rejection, confidence tiering, npm/OSV version evaluation, and reporting.

To remove global commands installed with `npm link`:

```bash
npm unlink -g <package-name>
```

Runtime dependencies are intentionally minimal: `commander`, `zod`, `semver`, and `@aws-sdk/client-s3`.

---

## Supported Ecosystems 

### What works today

- **npm:** full `package-lock.json` (v1, v2, v3) parsing, including direct vs. transitive dependencies, scoped packages, and deduplication.
- **Python:** `requirements.txt` with exact pins (`pkg==1.2.3`). Ranges and VCS lines are skipped and reported, never guessed.
- **Signing:** Ed25519 over DSSE pre-authentication encoding. Changing one byte of a signed SBOM, or verifying with the wrong key, fails verification.
- **KEV polling:** Zod schema validation plus local caching, so a network failure can't silently report "no vulnerabilities".

### Known limitations

- **Lockfile coverage:** no `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `go.sum`, or `Cargo.lock` support yet.
- **No CPE matching:** KEV's free-text fields are the only matching signal. An NVD/OSV-backed provider with real affected-version ranges would sharpen the `low` tier.
- **Version intelligence is npm-only:** Python packages don't yet get OSV version evaluation.
- **Local-key signing:** Ed25519 with local keys, not Sigstore keyless or a transparency log. The envelope shape stays the same if you upgrade to cosign later.
- **KEV feed verification:** the poller was verified end-to-end against a synthetic snapshot matching the real response shape. Confirm behavior against the live CISA feed in your own environment.

---



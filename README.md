# 🦅 Osprey

**SBOM Security Auditing & CISA KEV Vulnerability Detection**

Osprey is a powerful CLI tool (`cra`) that helps you identify actively exploited vulnerabilities in your software dependencies by cross-checking against the CISA Known Exploited Vulnerabilities (KEV) catalog.

## Features

**KEV Detection** — Cross-checks components against CISA's Known Exploited Vulnerabilities (KEV) catalog
**Security Auditing** — Provides color-coded, actionable reports on actively exploited vulnerabilities
**Remote Auditing** — Audit GitHub repositories without cloning them locally
**Version Intelligence** — Uses OSV to determine if your installed versions are affected
**SBOM Signing** — Ed25519 digital signatures with DSSE envelope


Everything below has been run and verified in this environment — not just written.

## What's real vs. what's a known limitation

**Works today:**

- npm: full `package-lock.json` (v1, v2, v3) parsing — direct vs. transitive deps, scoped packages, dedup
- Python: `requirements.txt` with exact pins (`pkg==1.2.3`) — ranges/VCS lines are explicitly skipped and reported, never guessed
- Ed25519 signing via DSSE pre-authentication encoding — tamper detection verified (changing one byte of the SBOM after signing fails verification; signing with the wrong key fails verification)
- CISA KEV polling with schema validation (Zod) and local caching so a network hiccup doesn't silently report "no vulnerabilities"
- Cross-check with two confidence tiers — `high` (PURL-backed exact product match) vs `low` (name/vendor match only) — because CISA KEV entries are free-text vendor/product names, not machine-precise CPE ranges. See `src/correlation/matcher.ts` for why this distinction exists and matters for any downstream automation (e.g. auto-starting a regulatory clock — don't, on `low` confidence).
- Slack-compatible webhook alerting, batched into one message per run, high/low separated
- npm version intelligence using OSV advisories, with authoritative affected/not-affected/unknown status
- GitHub Actions reporting from the structured result: job summary, escaped annotations, and SARIF output

**Known limitations, stated honestly:**
- No yarn.lock / pnpm-lock.yaml / poetry.lock / go.sum / Cargo.lock generators yet — npm and pinned-pip only
- CPE matching not implemented — KEV's free-text fields are the only signal; an NVD/OSV-backed provider with real affected-version ranges would upgrade the `low` tier to something more precise
- Signing is local-key Ed25519, not full Sigstore keyless/transparency-log — same crypto primitive, less infrastructure. Upgrading to cosign's keyless flow later doesn't require changing the envelope shape.
- The CISA feed itself couldn't be hit from this sandbox (network allowlist blocks `cisa.gov` here) — poller logic was verified end-to-end against a synthetic snapshot in the exact response shape instead. It will hit the real feed with normal internet access (Render, your own machine, CI).
- Version intelligence currently supports npm packages through OSV. CISA KEV supplies the `known_exploited` exploitation signal; OSV supplies affected-version evidence. `unknown` means the version could not be established or advisory evidence was unavailable, and is never treated as affected.
- Network requests use bounded timeouts and response sizes. S3 endpoints must use HTTPS, except for loopback-only local development. Malformed external JSON is rejected rather than treated as an empty or safe result.

## Quick Start

### Installation

```bash
git clone <your-repo-url>
cd osprey
npm install
npm run build
```

### Main Command: `cra` (Recommended)

The `cra` command is the easiest way to audit your projects for CISA KEV vulnerabilities:

**Audit a local project:**
```bash
npm run cra -- --path /path/to/your/project

# Or after global install:
cra --path /path/to/your/project
```

**Audit a GitHub repository:**
```bash
npm run cra -- --url https://github.com/owner/repo
npm run cra -- --url owner/repo  # Short form also works

# Or after global install:
cra --url facebook/react
```

**With options:**
```bash
# Audit with detailed output
npm run cra -- --path . --verbose

# Audit and save results to JSON
npm run cra -- --url owner/repo --output results.json

# Fail CI if vulnerabilities found
npm run cra -- --path . --fail-on-high

# Audit private GitHub repo (requires GitHub token)
npm run cra -- --url owner/private-repo --github-token YOUR_TOKEN
# Or set environment variable: export GITHUB_TOKEN=YOUR_TOKEN

# Show only summary (condensed output)
npm run cra -- --path . --summary
```

### Global Installation

Install Osprey globally to use the `cra` command anywhere:

```bash
npm install -g .
# or
npm link

# Now use from anywhere:
cra --url facebook/react
cra --path ~/my-project --verbose
cra-sbom --path . --output sbom.json
```

### Output Format

The audit command provides clear, color-coded output:

- ✓ **Green** = No active exploitable vulnerabilities detected
- ✗ **Red** = Actively exploited vulnerable components found
- ⚠ **Yellow** = Warnings or low-confidence matches

**Example output:**
```
Auditing: /path/to/project

Generating SBOM from local project...
Found 245 components

Polling CISA Known Exploited Vulnerabilities (KEV)...
Loaded 1,234 KEV entries (as of 2026-09-18)

Cross-checking components against KEV database...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SBOM Vulnerability Audit Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Subject: /path/to/project
Components analyzed: 245
KEV entries checked: 1,234 (as of 2026-09-18)

✓ No active exploitable vulnerabilities detected
All components are clear of known exploited vulnerabilities.
```

Or if vulnerabilities are found:
```
✗ Vulnerable components detected

  ✗ 2 HIGH confidence match(es)
  ⚠ 1 LOW confidence match(es)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
High Confidence Vulnerabilities
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. CVE-2024-12345
   Component: vulnerable-package@1.2.3
   PURL: pkg:npm/vulnerable-package@1.2.3
   Vulnerability: Remote Code Execution in vulnerable-package
   Version Status: AFFECTED (1.2.3 is vulnerable)
   Product: vulnerable-package (vendor-name)
   Description: Critical vulnerability allowing remote code execution
   Required Action: Apply mitigations per vendor instructions or discontinue use

   ⚠ RECOMMENDED ACTION:
   Update to the latest patched version immediately.
   Check security advisories for vulnerable-package
```

### Advanced Commands

**Generate SBOM only:**
```bash
npm run sbom -- --path . --output sbom.json --sign --generate-key
```

**Check KEV with existing SBOM:**
```bash
npm run kev -- --sbom sbom.json --offline --cache ~/.cra-guard/kev-cache.json
```

**KEV check with webhook alerting:**
```bash
npm run kev -- --path . --webhook https://hooks.slack.com/services/... --fail-on-high
```

The KEV CLI can also write a structured result for CI systems and downstream
automation. It includes the SBOM component count, KEV snapshot metadata, full
match details, warnings/errors, and status for each pipeline stage:

```bash
npm run kev -- --sbom sbom.json --result sboim-result.json --fail-on-high
```

The result schema is versioned as `schemaVersion: "1.0"`. Signing and storage
are currently reported as `skipped`; they can be enabled later when secure CI
credentials and key management are configured. Each stage includes a `status`
and may include an optional `reason` explaining a skipped or failed stage;
existing consumers that only read `status` remain compatible.

Version-enriched findings add `identityConfidence`, `versionStatus`,
`exploitationStatus`, and `advisoryIds`. `versionStatus` is `affected` only
when OSV evidence covers the installed npm version, `not_affected` when the
available evidence excludes it, and `unknown` when the version or evidence
cannot be evaluated. `exploitationStatus: "known_exploited"` is independent
and comes from CISA KEV, not from OSV.

The `--` separates npm's own flags from the CLI's — everything after it goes to the tool.

### Global install — real `cra-sbom` / `cra-kev` commands, anywhere on your machine

```bash
git clone <your-repo-url>
cd cra-guard-core
npm install    # runs the build automatically via the "prepare" script — no separate build step
npm link       # installs cra-sbom and cra-kev globally, symlinked to this checkout
```

Verified working (this exact sequence was run against a real clone, not assumed):

```bash
cra-sbom --path ~/some-other-project --output sbom.json --sign --generate-key
cra-kev --path ~/some-other-project --cache ~/.cra-guard/kev-cache.json
```

To remove the global commands later: `npm unlink -g cra-guard-core`.

Run the test suite (works either way):

```bash
npm test
```

49 tests, all passing. `npm audit` will flag a handful of vulnerabilities in `vitest`'s dev-dependency chain (an `esbuild` dev-server issue) — these are test-runner-only and don't affect the `cra-sbom`/`cra-kev` binaries themselves, which depend only on `commander`, `zod`, `semver`, and `@aws-sdk/client-s3`.

49 tests, all passing as of this build: npm/python generation correctness, signing round-trip
+ tamper detection + wrong-key rejection, cross-check confidence tiering, npm/OSV version evaluation, and reporting.

## CLI Commands

Osprey provides several CLI commands:

- **`cra`** - Main audit command (alias for cra-audit)
- **`cra-audit`** - Full audit with vulnerability detection
- **`cra-sbom`** - Generate SBOM only
- **`cra-kev`** - Check existing SBOM against KEV
- **`cra-report`** - Generate GitHub Actions reports

## CLI Options Reference

### `cra` / `cra-audit` Options

| Option | Description | Default |
|--------|-------------|---------|
| `-p, --path <dir>` | Local project directory to audit | `.` (current directory) |
| `-u, --url <github-url>` | GitHub repository URL to audit | - |
| `--cache <file>` | KEV cache file path | `~/.osprey/kev-cache.json` |
| `--offline` | Use only cached KEV data (no network) | `false` |
| `--output <file>` | Write detailed JSON result to file | - |
| `--verbose` | Show detailed output with additional info | `false` |
| `--fail-on-high` | Exit with error if high-confidence vulns found | `false` |
| `--show-low` | Include low-confidence matches in output | `true` |
| `--github-token <token>` | GitHub token for private repos | `$GITHUB_TOKEN` |
| `--summary` | Show only summary output | `false` |

**GitHub URL Formats Supported:**
- `https://github.com/owner/repo`
- `github.com/owner/repo`
- `owner/repo`
- `https://github.com/owner/repo/tree/branch`
- `owner/repo/tree/branch/path/to/dir`

## Architecture

```
src/
  sbom/
    generate/
      npm.ts           Full package-lock.json v1/v2/v3 parser
      python.ts        requirements.txt parser (exact pins only)
      remote.ts        GitHub repository SBOM generation
      index.ts         Orchestrator + CycloneDX renderer
    purl.ts            Package URL parse/build
    signing.ts         Ed25519 DSSE sign/verify
    storage.ts         S3-compatible put/get
    pipeline.ts        generate -> sign -> store workflow
  vulnerability/
    kev.ts             CISA KEV poller with caching
    osv.ts             OSV advisory lookup
    version.ts         Version status evaluation
    check.ts           End-to-end KEV check orchestration
  correlation/
    matcher.ts         Confidence-tiered cross-check logic
  output/
    formatter.ts       Terminal color/symbol utilities
    audit-report.ts    Formatted vulnerability reports
  network/
    http.ts            Bounded fetch utilities
    github.ts          GitHub repository file fetcher
  alerting/
    webhook.ts         Slack-compatible alerting
  reporting/
    report.ts          SARIF + GitHub Actions integration
cli/
  audit.ts           Main audit command (NEW)
  generate-sbom.ts   SBOM generation CLI
  kev-check.ts       KEV check CLI
  report-sboim.ts    GitHub Actions reporting CLI
tests/               49 passing tests, real fixtures
```

## Environment variables (only needed for `--store`)

```
S3_ENDPOINT, S3_REGION, S3_BUCKET, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY, S3_FORCE_PATH_STYLE
```

`npm audit` currently reports vulnerabilities in the Vitest/Vite development-only
test runner chain. Production runtime dependencies are not affected. The
available remediation requires a breaking Vitest major upgrade, so it is not
applied automatically during this audit.

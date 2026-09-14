# cra-guard-core

Two standalone, independently sellable pieces:

1. **KEV poller + cross-check + alerting** — pulls the live CISA KEV feed, cross-checks
   it against an SBOM's components with confidence tiering, and alerts via Slack webhook
   or console output. Exits non-zero on high-confidence matches for CI gating.

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

**Known limitations, stated honestly:**
- No yarn.lock / pnpm-lock.yaml / poetry.lock / go.sum / Cargo.lock generators yet — npm and pinned-pip only
- CPE matching not implemented — KEV's free-text fields are the only signal; an NVD/OSV-backed provider with real affected-version ranges would upgrade the `low` tier to something more precise
- Signing is local-key Ed25519, not full Sigstore keyless/transparency-log — same crypto primitive, less infrastructure. Upgrading to cosign's keyless flow later doesn't require changing the envelope shape.
- The CISA feed itself couldn't be hit from this sandbox (network allowlist blocks `cisa.gov` here) — poller logic was verified end-to-end against a synthetic snapshot in the exact response shape instead. It will hit the real feed with normal internet access (Render, your own machine, CI).
- Version intelligence currently supports npm packages through OSV. CISA KEV supplies the `known_exploited` exploitation signal; OSV supplies affected-version evidence. `unknown` means the version could not be established or advisory evidence was unavailable, and is never treated as affected.

## Usage

### Quick — run from source, no build

```bash
git clone <your-repo-url>
cd cra-guard-core
npm install

npm run sbom -- --path . --output sbom.json --sign --generate-key
npm run kev -- --path . --webhook https://hooks.slack.com/services/... --fail-on-high
npm run kev -- --sbom sbom.json --offline --cache ~/.cra-guard/kev-cache.json
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

44 tests, all passing. `npm audit` will flag a handful of vulnerabilities in `vitest`'s dev-dependency chain (an `esbuild` dev-server issue) — these are test-runner-only and don't affect the `cra-sbom`/`cra-kev` binaries themselves, which depend only on `commander`, `zod`, `semver`, and `@aws-sdk/client-s3`.

44 tests, all passing as of this build: npm/python generation correctness, signing round-trip
+ tamper detection + wrong-key rejection, cross-check confidence tiering, and npm/OSV version evaluation.

## Layout

```
src/sbom/
  generate/       npm.ts, python.ts, index.ts (orchestrator + CycloneDX renderer)
  purl.ts         Package URL parse/build
  signing.ts      Ed25519 DSSE sign/verify
  storage.ts      S3-compatible put/get
  pipeline.ts     generate -> sign -> store, wired together
src/vulnerability/
  kev.ts          CISA KEV poller with caching
src/correlation/
  matcher.ts      confidence-tiered cross-check
src/alerting/
  webhook.ts      Slack-compatible alerting
cli/
  generate-sbom.ts
  kev-check.ts
tests/            44 passing tests, real fixtures
```

## Environment variables (only needed for `--store`)

```
S3_ENDPOINT, S3_REGION, S3_BUCKET, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY, S3_FORCE_PATH_STYLE
```

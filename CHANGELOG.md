# Changelog

All notable changes to Osprey will be documented in this file.

## [0.1.0] - 2026-09-19

### 🎉 Project Rebranded: Osprey

The project has been renamed from `cra-guard-core` to **Osprey** with the CLI alias `cra`.

### ✨ New Features

#### Main Audit Command (`cra`)
- **New primary command**: `cra` - Simple, memorable alias for auditing projects
- **Color-coded output** with visual indicators:
  - ✓ Green for no vulnerabilities
  - ✗ Red for actively exploited components
  - ⚠ Yellow for warnings and low-confidence matches
- **Enhanced reporting** with detailed vulnerability information
- **Summary mode** for quick security status checks
- **Verbose mode** for comprehensive audit details

#### GitHub Repository Auditing
- **Remote auditing** without cloning repositories
- **Multiple URL format support**:
  - `owner/repo`
  - `https://github.com/owner/repo`
  - `owner/repo/tree/branch`
  - `owner/repo/tree/branch/path/to/dir`
- **Private repository support** via GitHub token
- **Branch and subdirectory** auditing
- **Automatic package manager detection** (npm, Python)

#### Professional Output Formatting
- **Terminal color support** with ANSI codes
- **Formatted tables** for vulnerability lists
- **Version status indicators**:
  - AFFECTED - Installed version is vulnerable
  - NOT AFFECTED - Version is safe
  - UNKNOWN - Cannot determine status
- **Confidence level display** (HIGH/LOW)
- **Actionable remediation advice** for each vulnerability
- **CVE and advisory information** with OSV integration

### 📦 New Modules

- `cli/audit.ts` - Main audit command implementation
- `src/output/formatter.ts` - Terminal formatting utilities
- `src/output/audit-report.ts` - Vulnerability report generator
- `src/network/github.ts` - GitHub repository file fetcher
- `src/sbom/generate/remote.ts` - Remote SBOM generation

### 🔧 CLI Commands

All commands now use the `cra` prefix:

- **`cra`** - Main audit command (NEW)
- **`cra-audit`** - Full alias for audit command
- **`cra-sbom`** - Generate SBOM only
- **`cra-kev`** - Check existing SBOM against KEV
- **`cra-report`** - Generate GitHub Actions reports

### 📝 Documentation

- **README.md** - Completely updated with Osprey branding
- **AUDIT_CLI_GUIDE.md** - Comprehensive user guide
- **CHANGELOG.md** - This file

### 🛠️ Breaking Changes

- **Project name** changed from `cra-guard-core` to `osprey`
- **Default cache directory** changed from `~/.cra-guard/` to `~/.osprey/`
- **Tool identifier** in SBOMs changed to `osprey-sbom-gen`
- **User-Agent header** changed to `osprey-sbom-audit`

### 🔄 Migration Guide

If you were using the old `cra-guard-core`:

1. **Cache location**: Move your KEV cache
   ```bash
   mv ~/.cra-guard ~/.osprey
   ```

2. **CLI commands**: Update your scripts
   - Old: `npm run audit`
   - New: `npm run cra` (shorter and simpler!)

3. **Package name**: Update any references
   - Old: `cra-guard-core`
   - New: `osprey`

### 📊 Features Summary

| Feature | Status |
|---------|--------|
| Local project auditing | ✅ Enhanced |
| GitHub repository auditing | ✅ NEW |
| Color-coded output | ✅ NEW |
| CISA KEV integration | ✅ Existing |
| Version intelligence (OSV) | ✅ Existing |
| Confidence tiering | ✅ Existing |
| SBOM generation (npm, Python) | ✅ Existing |
| Ed25519 SBOM signing | ✅ Existing |
| S3 storage | ✅ Existing |
| GitHub Actions integration | ✅ Existing |
| Slack webhook alerts | ✅ Existing |
| Offline mode | ✅ Existing |
| CI/CD fail-on-high | ✅ Enhanced |

### 🧪 Testing

- All 49 existing tests passing
- TypeScript compilation successful
- CLI commands tested and verified

### 🎯 Quick Start Examples

**Audit current project:**
```bash
npm run cra
```

**Audit GitHub repository:**
```bash
npm run cra -- --url facebook/react
```

**CI/CD security gate:**
```bash
npm run cra -- --path . --fail-on-high
```

**Save detailed results:**
```bash
npm run cra -- --path . --output results.json
```

---

## Legacy Version History

Previous versions were released as `cra-guard-core`:

### [0.0.x] - Earlier releases
- Initial SBOM generation for npm and Python
- CISA KEV polling and cross-checking
- Ed25519 signing with DSSE
- S3-compatible storage
- GitHub Actions integration
- Slack webhook alerts
- OSV version intelligence

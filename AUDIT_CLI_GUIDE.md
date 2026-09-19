# 🦅 Osprey CLI - User Guide

## Overview

**Osprey** (`cra`) is a comprehensive CLI tool for auditing Software Bill of Materials (SBOM) against the CISA Known Exploited Vulnerabilities (KEV) catalog. It provides actionable, color-coded reports highlighting actively exploited vulnerabilities in your dependencies.

The main command is `cra` (short and memorable), with additional specialized commands like `cra-sbom`, `cra-kev`, and `cra-report` for specific workflows.

## Features

✅ **Local Project Auditing** - Scan any npm or Python project on your filesystem
✅ **Remote GitHub Auditing** - Audit public/private GitHub repos without cloning
✅ **CISA KEV Integration** - Real-time checking against known exploited vulnerabilities
✅ **Color-Coded Output** - Clear visual indicators (✓ green, ✗ red, ⚠ yellow)
✅ **Confidence Levels** - High/low confidence matching to reduce false positives
✅ **Version Intelligence** - Uses OSV to determine if installed versions are affected
✅ **CI/CD Integration** - Fail builds on high-confidence vulnerabilities
✅ **Offline Mode** - Use cached KEV data when network is unavailable

## Installation

```bash
git clone <your-repo-url>
cd osprey
npm install
npm run build

# Optional: Install globally for the 'cra' command
npm link
```

## Quick Start

### Audit a Local Project

```bash
# Using npm run (from project directory)
npm run cra

# After global install
cra

# Audit a specific directory
cra --path /path/to/your/project

# Get detailed output
cra --verbose
```

### Audit a GitHub Repository

```bash
# Public repository
cra --url https://github.com/facebook/react
cra --url facebook/react  # Short form

# Private repository (requires token)
export GITHUB_TOKEN=your_github_token
cra --url company/private-repo

# Or pass token directly
cra --url company/private-repo --github-token YOUR_TOKEN
```

### Common Use Cases

#### 1. **CI/CD Security Gate**

Fail your build if actively exploited vulnerabilities are found:

```bash
cra --path . --fail-on-high
```

Exit codes:
- `0` = No high-confidence vulnerabilities found
- `1` = High-confidence vulnerabilities detected OR error occurred

#### 2. **Save Audit Results**

```bash
cra --path . --output audit-results.json
```

The JSON output includes:
- SBOM component count
- KEV snapshot metadata
- Detailed match information
- Version status for each finding
- Advisory IDs and CVE references

#### 3. **Quick Summary**

Get a condensed report:

```bash
cra --path . --summary
```

Output:
```
✓ No active exploitable vulnerabilities detected
```

Or if vulnerabilities exist:
```
✗ Found 2 actively exploited vulnerable component(s)

  ✗  axios           0.21.1  CVE-2021-3749   AFFECTED
  ✗  lodash          4.17.19 CVE-2020-8203   AFFECTED
```

#### 4. **Offline Auditing**

Use cached KEV data without internet:

```bash
cra --path . --offline
```

## CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `-p, --path <dir>` | Local project directory to audit | `.` |
| `-u, --url <url>` | GitHub repository URL | - |
| `--cache <file>` | KEV cache file path | `~/.osprey/kev-cache.json` |
| `--offline` | Use cached KEV data only | `false` |
| `--output <file>` | Write JSON results to file | - |
| `--verbose` | Show detailed information | `false` |
| `--fail-on-high` | Exit with error on high-confidence matches | `false` |
| `--show-low` | Include low-confidence matches | `true` |
| `--github-token` | GitHub personal access token | `$GITHUB_TOKEN` |
| `--summary` | Show condensed output | `false` |

## Understanding the Output

### Status Indicators

- **✓ Green** = No active exploitable vulnerabilities
- **✗ Red** = Actively exploited vulnerable components
- **⚠ Yellow** = Warnings or low-confidence matches

### Confidence Levels

#### High Confidence
- Component has a Package URL (PURL) from lockfile
- Exact product name match with KEV entry
- Strong package identity (handles scoped packages correctly)
- **Recommended**: Act on these findings immediately

#### Low Confidence
- Only vendor/product name match
- No PURL corroboration
- **Recommended**: Review manually before taking action

### Version Status

- **AFFECTED** (Red) - Installed version is vulnerable per OSV evidence
- **NOT AFFECTED** (Green) - Installed version is outside vulnerable range
- **UNKNOWN** (Yellow) - Version status cannot be determined

### Example Report

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SBOM Vulnerability Audit Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Subject: /path/to/project
Components analyzed: 245
KEV entries checked: 1,234 (as of 2026-09-18)

✗ Vulnerable components detected

  ✗ 2 HIGH confidence match(es)
  ⚠ 1 LOW confidence match(es)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
High Confidence Vulnerabilities
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. CVE-2021-44228
   Component: log4j-core@2.14.1
   PURL: pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1
   Vulnerability: Apache Log4j2 Remote Code Execution
   Version Status: AFFECTED (2.14.1 is vulnerable)
   Product: log4j (Apache)
   Description: Remote code execution in Log4j 2.x
   Required Action: Update to version 2.17.1 or later
   Due Date: 2021-12-24
   ⚠ Known Ransomware Use

   ⚠ RECOMMENDED ACTION:
   Update to the latest patched version immediately.
   Check security advisories for log4j-core

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Summary
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Status: FAILED
Total matches: 3
  - High confidence: 2
  - Low confidence: 1

Audit completed in 3.45s
```

## GitHub Repository Auditing

### Supported URL Formats

```bash
# Full HTTPS URL
cra --url https://github.com/owner/repo

# Short form (domain optional)
cra --url owner/repo
cra --url github.com/owner/repo

# Specific branch
cra --url https://github.com/owner/repo/tree/develop

# Subdirectory
cra --url owner/repo/tree/main/packages/frontend
```

### Private Repositories

Set your GitHub token as an environment variable:

```bash
export GITHUB_TOKEN=ghp_your_token_here
cra --url company/private-repo
```

Or pass it directly:

```bash
cra --url company/private-repo --github-token ghp_your_token_here
```

**Generating a GitHub Token:**

1. Go to https://github.com/settings/tokens
2. Click "Generate new token (classic)"
3. Select scopes: `repo` (for private repos) or no scopes (for public only)
4. Copy the token

### Supported Package Managers

The CLI automatically detects and analyzes:

- **npm** - Reads `package-lock.json` (v1, v2, v3)
- **Python** - Reads `requirements.txt` (exact pins only)

If neither file is found, you'll get an error message.

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '20'

      - name: Install Osprey
        run: |
          git clone https://github.com/your-org/osprey.git
          cd osprey
          npm install
          npm run build

      - name: Run Security Audit
        run: |
          cd osprey
          npm run cra -- --path $GITHUB_WORKSPACE --fail-on-high --output audit-results.json

      - name: Upload Results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: audit-results
          path: osprey/audit-results.json
```

### GitLab CI Example

```yaml
security_audit:
  stage: test
  image: node:20
  script:
    - git clone https://github.com/your-org/osprey.git
    - cd osprey
    - npm install
    - npm run build
    - npm run cra -- --path $CI_PROJECT_DIR --fail-on-high --output audit-results.json
  artifacts:
    paths:
      - osprey/audit-results.json
    when: always
```

## Troubleshooting

### "No supported package file found"

**Problem**: The CLI cannot find `package-lock.json` or `requirements.txt`

**Solutions**:
- Ensure you're in the correct directory
- For npm projects, run `npm install` to generate package-lock.json
- For Python, ensure requirements.txt exists with exact pins (==)

### "HTTP 404" when auditing GitHub repo

**Problem**: Repository not found or private without authentication

**Solutions**:
- Check the URL format is correct
- For private repos, provide a GitHub token
- Ensure the token has `repo` scope for private repositories

### "Failed to fetch package.json"

**Problem**: npm projects require package.json to exist

**Solutions**:
- Ensure package.json exists in the repository
- For monorepos, specify the subdirectory path in the URL

### "KEV entries: 0"

**Problem**: KEV cache is empty or stale

**Solutions**:
- Remove `--offline` flag to fetch fresh data
- Delete the cache file: `rm ~/.osprey/kev-cache.json`
- Check internet connectivity

## Advanced Usage

### Monitoring Multiple Repositories

Create a script to audit multiple repos:

```bash
#!/bin/bash
# audit-all.sh

REPOS=(
  "facebook/react"
  "vuejs/vue"
  "angular/angular"
)

for repo in "${REPOS[@]}"; do
  echo "Auditing $repo..."
  cra --url "$repo" --output "results-$(echo $repo | tr '/' '-').json"
done
```

### Scheduled Audits with Cron

```bash
# Add to crontab -e (assumes global install)
0 9 * * * cra --url company/project --fail-on-high >> /var/log/audit.log 2>&1
```

### Custom KEV Cache Location

```bash
cra --cache /custom/path/kev-cache.json
```

### Combining with Other Tools

```bash
# Generate SBOM, then audit it
cra-sbom --path . --output sbom.json
cra --path . --output audit.json

# Compare results over time
diff audit-yesterday.json audit-today.json
```

## FAQ

**Q: How often is the CISA KEV database updated?**
A: CISA updates the KEV catalog regularly. The CLI caches the data locally and includes timestamps to show data freshness.

**Q: Can I audit repositories in other languages (Go, Rust, Java)?**
A: Currently, only npm (JavaScript/TypeScript) and Python (requirements.txt) are supported. Support for other ecosystems is planned.

**Q: What's the difference between this and `npm audit`?**
A: `npm audit` checks all known vulnerabilities. This tool specifically checks for **actively exploited** vulnerabilities from CISA's KEV catalog, which represents real-world exploitation.

**Q: How do I know if I should act on a "low confidence" match?**
A: Low confidence matches should be manually reviewed. Check if the component name/vendor actually matches the KEV entry details before taking action.

**Q: Can I use this in a Docker container?**
A: Yes! Osprey works in any Node.js 20+ environment.

```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY . .
RUN npm install && npm run build && npm link
CMD ["cra", "--path", "/project"]
```

## Support

For issues, questions, or contributions:
- GitHub Issues: [your-repo-url]/issues
- Documentation: See README.md for technical details

## License

See LICENSE file in the repository.

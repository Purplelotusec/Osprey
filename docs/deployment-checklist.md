# Deployment Checklist for purplelotus.space

## Pre-Deployment

- [ ] Update GitHub repository URL in install.sh if needed
- [ ] Test installer locally
- [ ] Verify all dependencies are in package.json
- [ ] Run `npm run build` successfully
- [ ] Test on clean environment

## GitHub Repository Setup

- [ ] Create repository: `purplelotus/osprey`
- [ ] Push code to main branch
- [ ] Set repository visibility (public recommended for open source)
- [ ] Add repository description
- [ ] Add topics/tags for discoverability

## Domain Setup (purplelotus.space)

### Option A: Direct Web Server

1. [ ] SSH into server
2. [ ] Copy install.sh to web root:
   ```bash
   scp install.sh user@purplelotus.space:/var/www/purplelotus.space/install-osprey.sh
   ```
3. [ ] Set correct permissions:
   ```bash
   chmod 644 /var/www/purplelotus.space/install-osprey.sh
   ```
4. [ ] Configure web server (Nginx/Apache) - see hosting-setup.md
5. [ ] Ensure HTTPS is enabled
6. [ ] Test access:
   ```bash
   curl -I https://purplelotus.space/install-osprey.sh
   ```

### Option B: GitHub Pages

1. [ ] Create repository: `purplelotus/purplelotus.github.io`
2. [ ] Copy files:
   - install-osprey.sh (from install.sh)
   - index.html (from docs/install-page.html)
3. [ ] Push to main branch
4. [ ] Configure custom domain in Settings → Pages
5. [ ] Add DNS records (CNAME and A records)
6. [ ] Wait for DNS propagation
7. [ ] Enable HTTPS in GitHub Pages settings

### Option C: Cloudflare Pages

1. [ ] Connect GitHub repository to Cloudflare Pages
2. [ ] Set build command: (none for static)
3. [ ] Set output directory: `/`
4. [ ] Add custom domain: purplelotus.space
5. [ ] Deploy

## Testing Installation

1. [ ] Test one-line installer:
   ```bash
   curl -fsSL https://purplelotus.space/install-osprey.sh | bash
   ```

2. [ ] Verify commands work:
   ```bash
   cra --help
   osprey --help
   ```

3. [ ] Test on different systems:
   - [ ] Ubuntu/Debian
   - [ ] macOS
   - [ ] RHEL/CentOS
   - [ ] Arch Linux

4. [ ] Test audit functionality:
   ```bash
   cra --path /path/to/test/project
   ```

## Documentation Updates

- [ ] Update README.md with correct URLs
- [ ] Add installation instructions to docs
- [ ] Create CONTRIBUTING.md
- [ ] Add LICENSE file
- [ ] Create CHANGELOG.md

## Post-Deployment

- [ ] Announce release
- [ ] Monitor server logs for install script access
- [ ] Set up monitoring/analytics (optional)
- [ ] Create GitHub release/tag
- [ ] Update version in package.json

## Verification Commands

```bash
# Check installer is accessible
curl -I https://purplelotus.space/install-osprey.sh

# Download and inspect
curl -fsSL https://purplelotus.space/install-osprey.sh | head -20

# Check landing page
curl -I https://purplelotus.space/

# Test full installation in Docker
docker run -it --rm node:20 bash
curl -fsSL https://purplelotus.space/install-osprey.sh | bash
cra --help
```

## Rollback Plan

If issues are found:

1. [ ] Keep backup of working install.sh
2. [ ] Have previous version accessible at versioned URL
3. [ ] Update install script to point to stable version
4. [ ] Notify users of issues via GitHub

## Maintenance

- [ ] Set up automated testing for installer
- [ ] Monitor GitHub issues for installation problems
- [ ] Update installer when breaking changes occur
- [ ] Keep hosting-setup.md documentation current

## Security Checks

- [ ] HTTPS is enforced (no HTTP access)
- [ ] Install script has correct permissions (644)
- [ ] No sensitive information in install script
- [ ] Repository access is properly configured
- [ ] Rate limiting is configured (if applicable)

## Quick Deploy Script

Save this as `deploy.sh`:

```bash
#!/bin/bash
set -e

echo "Deploying Osprey installer to purplelotus.space..."

# Copy installer
scp install.sh user@purplelotus.space:/var/www/purplelotus.space/install-osprey.sh

# Copy landing page
scp docs/install-page.html user@purplelotus.space:/var/www/purplelotus.space/index.html

# Set permissions
ssh user@purplelotus.space "chmod 644 /var/www/purplelotus.space/install-osprey.sh"
ssh user@purplelotus.space "chmod 644 /var/www/purplelotus.space/index.html"

# Test
echo "Testing installer..."
curl -fsSL https://purplelotus.space/install-osprey.sh | head -5

echo "Deployment complete!"
echo "Install URL: https://purplelotus.space/install-osprey.sh"
echo "Landing page: https://purplelotus.space/"
```

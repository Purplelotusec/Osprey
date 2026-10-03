# Hosting Setup for purplelotus.space

## Overview

To enable the one-line installer, you need to host `install.sh` at `https://purplelotus.space/install-osprey.sh`

## Setup Options

### Option 1: Static File Hosting (Recommended)

Host the install script as a static file on your web server.

**Nginx Configuration:**

```nginx
server {
    listen 80;
    listen 443 ssl;
    server_name purplelotus.space;

    # SSL configuration
    ssl_certificate /path/to/ssl/cert.pem;
    ssl_certificate_key /path/to/ssl/key.pem;

    root /var/www/purplelotus.space;
    index index.html;

    # Serve install script
    location = /install-osprey.sh {
        alias /var/www/purplelotus.space/install-osprey.sh;
        add_header Content-Type text/plain;
        add_header Access-Control-Allow-Origin *;
    }

    # Main site
    location / {
        try_files $uri $uri/ =404;
    }
}
```

**Apache Configuration:**

```apache
<VirtualHost *:80>
    ServerName purplelotus.space
    DocumentRoot /var/www/purplelotus.space

    <Directory /var/www/purplelotus.space>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    # Redirect to HTTPS
    RewriteEngine On
    RewriteCond %{HTTPS} off
    RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
</VirtualHost>

<VirtualHost *:443>
    ServerName purplelotus.space
    DocumentRoot /var/www/purplelotus.space

    SSLEngine on
    SSLCertificateFile /path/to/ssl/cert.pem
    SSLCertificateKeyFile /path/to/ssl/key.pem

    <Directory /var/www/purplelotus.space>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    # Set correct MIME type for shell scripts
    <Files "install-osprey.sh">
        ForceType text/plain
        Header set Access-Control-Allow-Origin "*"
    </Files>
</VirtualHost>
```

**File Structure:**

```
/var/www/purplelotus.space/
├── index.html
├── install-osprey.sh         # Copy from SBOIM/install.sh
└── docs/
    └── osprey/
        └── README.md
```

### Option 2: GitHub Pages with Custom Domain

1. Create a new repository: `purplelotus/purplelotus.github.io`
2. Add `install-osprey.sh` to the root
3. Configure custom domain in repository settings:
   - Settings → Pages → Custom domain: `purplelotus.space`
4. Add DNS records:
   ```
   Type: CNAME
   Name: www
   Value: purplelotus.github.io

   Type: A
   Name: @
   Value: 185.199.108.153
          185.199.109.153
          185.199.110.153
          185.199.111.153
   ```

### Option 3: Cloudflare Pages

1. Connect your GitHub repository to Cloudflare Pages
2. Set custom domain: `purplelotus.space`
3. Deploy - the install script will be available automatically

### Option 4: CDN/Object Storage

**AWS S3 + CloudFront:**

```bash
# Upload to S3
aws s3 cp install.sh s3://purplelotus-public/install-osprey.sh \
  --content-type "text/plain" \
  --acl public-read

# Configure CloudFront distribution
# Point purplelotus.space to CloudFront
```

**Cloudflare R2:**

```bash
# Upload to R2
wrangler r2 object put purplelotus-public/install-osprey.sh \
  --file=install.sh \
  --content-type="text/plain"
```

## Deployment Steps

1. **Copy the install script:**
   ```bash
   cp /path/to/SBOIM/install.sh /var/www/purplelotus.space/install-osprey.sh
   chmod 644 /var/www/purplelotus.space/install-osprey.sh
   ```

2. **Verify it's accessible:**
   ```bash
   curl -fsSL https://purplelotus.space/install-osprey.sh | head -n 5
   ```

3. **Test the installer:**
   ```bash
   curl -fsSL https://purplelotus.space/install-osprey.sh | bash
   ```

## Security Considerations

1. **HTTPS Only:** Always serve the install script over HTTPS
2. **Integrity Check:** Consider adding SHA256 checksum verification
3. **Version Pinning:** Add version tags to the installer
4. **Rate Limiting:** Prevent abuse with rate limiting

## Optional: Version Management

Create versioned installers:

```
/var/www/purplelotus.space/
├── install-osprey.sh          # Latest (symlink)
├── install-osprey-v1.0.0.sh
├── install-osprey-v1.1.0.sh
└── versions.json
```

**versions.json:**
```json
{
  "latest": "1.1.0",
  "stable": "1.0.0",
  "versions": [
    {
      "version": "1.1.0",
      "url": "https://purplelotus.space/install-osprey-v1.1.0.sh",
      "sha256": "abc123..."
    },
    {
      "version": "1.0.0",
      "url": "https://purplelotus.space/install-osprey-v1.0.0.sh",
      "sha256": "def456..."
    }
  ]
}
```

## Monitoring

Track installer usage with:

1. **Server Logs:** Monitor access logs for install script downloads
2. **Analytics:** Add analytics to track installations (optional)
3. **Error Tracking:** Monitor failed installations

## Updates

When updating the installer:

```bash
# Update script on server
scp install.sh user@purplelotus.space:/var/www/purplelotus.space/install-osprey.sh

# Or automated deployment
git push origin main  # If using GitHub Pages/Cloudflare Pages
```

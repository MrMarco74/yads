# YADS - Comprehensive User Guide
**Version:** 1.17.0
**Last Updated:** 2026-01-26

Welcome to the **YADS (Yet Another Domain Scanner)** manual. This guide covers all aspects of the application, from running your first scan to advanced configuration and report generation.

---

## Table of Contents

1.  [Introduction](#1-introduction)
2.  [Getting Started](#2-getting-started)
3.  [Dashboard Overview](#3-dashboard-overview)
4.  [Target Management](#4-target-management)
5.  [Running Scans](#5-running-scans)
6.  [Scanner Modules Reference](#6-scanner-modules-reference)
7.  [Report Builder](#7-report-builder)
8.  [OSINT Brand Monitoring](#8-osint-brand-monitoring)
9.  [Visualizations](#9-visualizations)
10. [Data Management & Reports](#10-data-management--reports)
11. [User Management & Security](#11-user-management--security)
12. [Multi-Tenancy](#12-multi-tenancy)
13. [System Settings & Queue](#13-system-settings--queue)
14. [API Keys Configuration](#14-api-keys-configuration)
15. [Best Practices](#15-best-practices)
16. [Troubleshooting](#16-troubleshooting)

---

## 1. Introduction

**YADS** is an automated security reconnaissance platform designed to map, analyze, and monitor internet-facing assets. It combines multiple scanning techniques—DNS enumeration, port scanning, web analysis, and vulnerability detection—into a single, easy-to-use interface.

### Key Features
*   **Asset Discovery**: Find subdomains, forgotten infrastructure, and shadow IT.
*   **Vulnerability Scanning**: Detect outdated software (CVEs), misconfigurations, and security issues.
*   **Visual Intelligence**: Capture screenshots and visualize network relationships.
*   **Continuous Monitoring**: Track changes over time with automatic change detection.
*   **Custom Reports**: Generate professional PDF reports with your own branding.
*   **Multi-User & Multi-Tenant**: Securely manage multiple teams or clients within one instance.

### Who Should Use This Guide?
This guide is written for all users, regardless of technical background:
- **Security Teams**: Learn how to run comprehensive scans and interpret results.
- **IT Administrators**: Understand asset discovery and infrastructure mapping.
- **Compliance Officers**: Use compliance reports and security grading features.
- **Executives**: Generate executive summary reports for stakeholder presentations.

---

## 2. Getting Started

### 2.1 Initial Setup Wizard (First Run)
Upon the first launch of a new instance, YADS presents a **Setup Wizard**. You must complete this 4-step process before accessing the dashboard:

1.  **License**: Enter your valid YADS license key.
2.  **Database**: Define a secure password for the internal PostgreSQL database.
3.  **Initialization**:
    *   **Upgrade**: Preserves existing data and runs schema migrations.
    *   **Purge (Factory Reset)**: **WARNING**: Deletes ALL data and starts fresh.
4.  **Admin Creation**: Create the first System Administrator account.

> **Re-running the Setup**:
> If you need to re-run this wizard, restart the container with `SETUP_COMPLETE=false`:
> ```bash
> docker compose run -e SETUP_COMPLETE=false -p 8000:8000 yads-api
> ```

### 2.2 Logging In
Navigate to your YADS instance (e.g., `https://yads.your-domain.com`).
*   **Login**: Enter your username and password.
*   **MFA**: If enabled, enter your Time-based One-Time Password (TOTP).

### 2.3 Your First Scan
1.  **Add a Target**: Use the input box at the top to enter a domain (e.g., `example.com`).
2.  **Run Scan**: Click the "Scan" button to start gathering data.
3.  **View Results**: Click on the target name to see detailed scan results.

---

## 3. Dashboard Overview

The Dashboard is your command center.

*   **Critical Attention HUD**: Highlights immediate threats (expired SSL, critical vulnerabilities).
*   **Stats Cards**: Quick view of Total Targets, Active Scans, and Queue status.
*   **Target List**: A paginated table of all your monitored domains.
    *   **Status Indicators**: Shows if a scan is `Idle`, `Queued`, `Running`, or `Failed`.
    *   **Health Checks**: Quick indicators for SSL status, online status, and risk score.
*   **Live Activity**: Shows real-time progress of running scans.

---

## 4. Target Management

### Adding Targets
*   **Single**: Enter a domain in the dashboard input.
*   **Bulk Import**: Upload a text file (one domain per line) or paste a list.

### Bulk Actions
Select multiple targets using checkboxes to perform batch operations:
*   **Bulk Scan**: Run specific scan modules for all selected targets.
*   **Bulk Delete**: Remove targets and their data.

### Filtering & Tags
Use filters to find specific targets by name, status, or custom tags. Tags help you organize targets (e.g., `production`, `development`, `critical`).

---

## 5. Running Scans

### Quick Scan
Click the "Play" button on a target to run the **Default Scan Profile** (DNS, Web Analysis, SSL Check).

### Custom Scan
On the **Target Details** page, click **"New Scan"** to select individual modules. You can choose exactly what to scan based on your needs.

### Scheduled Scans
Automate your reconnaissance with recurring schedules:
1.  Navigate to **Schedules** in the sidebar.
2.  Click **"Create Schedule"**.
3.  Select a Target and Frequency (**Daily** or **Weekly**).

---

## 6. Scanner Modules Reference

YADS includes 17 specialized scanner modules. Each module gathers different types of intelligence about your targets.

### 6.1 DNS Scanner
**What it does**: Queries DNS servers to discover all DNS records associated with a domain.

**What it finds**:
- **A Records**: IPv4 addresses where the domain points
- **AAAA Records**: IPv6 addresses
- **MX Records**: Mail servers that handle email for the domain
- **TXT Records**: Text records (often contain SPF, DKIM, verification tokens)
- **NS Records**: Nameservers authoritative for the domain
- **CNAME Records**: Alias records pointing to other domains
- **SOA Record**: Start of Authority with zone information

**Why it matters**: DNS records reveal the infrastructure behind a domain, identify email servers, and can expose forgotten or misconfigured services.

**Security insights**:
- Dangling CNAMEs (pointing to non-existent resources) can be hijacked
- Missing or weak SPF/DMARC records enable email spoofing
- Exposed internal hostnames can reveal network structure

---

### 6.2 Subdomain Scanner
**What it does**: Discovers all subdomains belonging to a domain using multiple techniques.

**Discovery methods**:
- **Certificate Transparency**: Searches public SSL certificate logs
- **Passive DNS**: Queries historical DNS databases
- **Wordlist Bruteforce**: Tests common subdomain names

**What it finds**:
- All discovered subdomains (e.g., `api.example.com`, `dev.example.com`)
- IP addresses for each subdomain
- Whether each subdomain is currently resolvable

**Why it matters**: Subdomains often host forgotten applications, development environments, or administrative panels. These are frequently targeted by attackers because they receive less security attention than the main domain.

**Example findings**:
- `staging.example.com` - A forgotten staging server
- `old-api.example.com` - A deprecated API that's still accessible
- `admin.example.com` - An administrative panel

---

### 6.3 SSL/TLS Scanner
**What it does**: Analyzes the SSL/TLS certificate and encryption configuration of a website.

**What it checks**:
- **Certificate validity**: Is the certificate expired or not yet valid?
- **Certificate issuer**: Who issued the certificate (Let's Encrypt, DigiCert, etc.)
- **Subject Alternative Names (SANs)**: Other domains covered by this certificate
- **Supported protocols**: Which TLS versions are enabled (TLS 1.2, 1.3)
- **Cipher suites**: The encryption algorithms the server accepts
- **Certificate chain**: Is the full certificate chain properly configured?

**Why it matters**:
- Expired certificates break user trust and cause browser warnings
- Weak cipher suites can be exploited by attackers
- Certificate details can reveal additional domains and infrastructure

**Security indicators**:
- Days until certificate expiration
- Whether the certificate is self-signed (not trusted by browsers)
- Support for deprecated protocols (SSLv3, TLS 1.0, TLS 1.1)

---

### 6.4 Web Analyzer
**What it does**: Visits the website like a real user and analyzes what it finds.

**What it discovers**:
- **Technology stack**: Web server (Nginx, Apache), CMS (WordPress, Drupal), frameworks (React, Angular)
- **Security headers**: Are important headers like HSTS, CSP, X-Frame-Options configured?
- **Page title and metadata**: What the site presents to users and search engines
- **Forms and login pages**: Whether authentication interfaces exist
- **Cookies**: What cookies the site sets and their security attributes

**Why it matters**:
- Outdated software versions may have known vulnerabilities
- Missing security headers can enable attacks like clickjacking and XSS
- Login pages are potential targets for credential attacks

**Example output**:
```
Server: nginx/1.18.0
Technology: WordPress 6.2, PHP 8.1, MySQL
Missing Headers: Content-Security-Policy, X-Content-Type-Options
Login Form Detected: Yes
```

---

### 6.5 Nuclei Vulnerability Scanner
**What it does**: Actively probes the target for known vulnerabilities using the Nuclei scanner engine with 5000+ detection templates.

**What it detects**:
- **CVEs**: Known vulnerabilities with CVE identifiers
- **Misconfigurations**: Exposed debug panels, default credentials, open directories
- **Information disclosure**: Version numbers, error messages, stack traces
- **Security issues**: SQL injection, XSS, SSRF vulnerabilities

**Severity levels**:
- **Critical**: Immediate exploitation possible, high impact
- **High**: Significant security risk requiring urgent attention
- **Medium**: Moderate risk, should be addressed in regular maintenance
- **Low**: Minor issues with limited security impact
- **Info**: Informational findings, not necessarily security issues

**Why it matters**: This is your primary tool for finding exploitable vulnerabilities. Critical and high severity findings should be addressed immediately.

> **Note**: This is an active scanner that sends requests to the target. Use only on systems you have permission to test.

---

### 6.6 Nmap Port Scanner
**What it does**: Probes the target for open network ports and identifies running services.

**What it finds**:
- **Open ports**: Which ports are accepting connections (22, 80, 443, 3306, etc.)
- **Services**: What software is listening (SSH, HTTP, MySQL, etc.)
- **Version detection**: Service version numbers when detectable
- **Operating system hints**: Clues about the underlying OS

**Common ports and their services**:
| Port | Service | Notes |
|------|---------|-------|
| 21 | FTP | File transfer (often insecure) |
| 22 | SSH | Secure shell access |
| 23 | Telnet | Unencrypted remote access (dangerous) |
| 25 | SMTP | Email sending |
| 80 | HTTP | Unencrypted web traffic |
| 443 | HTTPS | Encrypted web traffic |
| 3306 | MySQL | Database |
| 3389 | RDP | Windows remote desktop |

**Why it matters**: Open ports reveal the attack surface. Unnecessary open ports (especially administrative services) should be closed or protected.

---

### 6.7 Infrastructure Scanner
**What it does**: Identifies the hosting infrastructure and network details for a target.

**What it discovers**:
- **IP geolocation**: Physical location of the server (country, city, region)
- **ASN information**: Which network the server belongs to
- **Hosting provider**: AWS, Google Cloud, DigitalOcean, etc.
- **ISP identification**: The internet service provider
- **Reverse DNS**: PTR records for the IP address

**Why it matters**:
- Helps identify shadow IT hosted on unexpected providers
- Geographic location may have compliance implications (GDPR, data residency)
- Understanding infrastructure aids incident response

---

### 6.8 Cloud Scanner
**What it does**: Searches for cloud storage buckets and containers associated with the domain.

**What it finds**:
- **S3 buckets**: Amazon Web Services storage
- **Azure blob containers**: Microsoft Azure storage
- **Google Cloud Storage**: GCP buckets
- **Public access**: Whether buckets are publicly accessible

**Why it matters**: Misconfigured cloud storage is a leading cause of data breaches. Public buckets can expose sensitive documents, backups, and customer data.

---

### 6.9 Typosquatting Scanner
**What it does**: Generates lookalike domain names and checks if they're registered.

**Techniques used**:
- **Character substitution**: `examp1e.com` (l → 1)
- **Adjacent key typos**: `examole.com` (p → o)
- **Character doubling**: `exammple.com`
- **Character omission**: `exampe.com`
- **TLD variations**: `example.co`, `example.net`

**What it checks for each variant**:
- Is the domain registered?
- Does it have an active website?
- Does it appear to impersonate your brand?

**Why it matters**: Typosquatting domains are used for phishing attacks against your customers and employees. Identifying them helps protect your brand.

---

### 6.10 Crawler
**What it does**: Systematically browses your website, following links to discover all pages and resources.

**What it discovers**:
- **Pages**: All accessible web pages
- **Forms**: Input forms (potential attack vectors)
- **Files**: Documents, PDFs, archives
- **Links**: Internal and external links
- **Emails**: Email addresses mentioned on pages
- **JavaScript files**: Client-side code
- **API endpoints**: Potential API paths found in code

**Why it matters**: The crawler maps the complete web application structure, revealing hidden pages, sensitive files, and attack surface you may not know about.

---

### 6.11 Wayback Machine Scanner
**What it does**: Searches the Internet Archive (Wayback Machine) for historical snapshots of the website.

**What it finds**:
- **Historical snapshots**: When the site was archived
- **Old URLs**: Pages that used to exist but are now removed
- **Historical technologies**: What the site used to run
- **Removed content**: Information that was previously public

**Why it matters**:
- Old URLs may still be accessible (forgotten endpoints)
- Historical snapshots can reveal sensitive information that was later removed
- Helps understand how the site has evolved

---

### 6.12 TLD Scanner
**What it does**: Checks if your domain name is registered across different top-level domains.

**What it checks**:
- Common TLDs: `.com`, `.net`, `.org`, `.io`, `.co`, etc.
- Country-code TLDs: `.uk`, `.de`, `.fr`, etc.
- New TLDs: `.app`, `.dev`, `.cloud`, etc.

**For each variation it reports**:
- Registration status (registered or available)
- Whether it has an active website
- Whether it appears related to your organization

**Why it matters**: Competitors or attackers may register your brand name under different TLDs. This can be used for brand confusion or phishing.

---

### 6.13 Content Discovery
**What it does**: Searches for hidden files and directories that aren't linked from the main site.

**What it finds**:
- **Backup files**: `.bak`, `.old`, `.backup` files
- **Configuration files**: `config.php`, `.env`, `settings.json`
- **Admin panels**: `/admin`, `/wp-admin`, `/administrator`
- **Development artifacts**: `.git`, `node_modules`, debug files
- **Documentation**: README files, changelogs

**Why it matters**: Hidden files often contain sensitive information like database credentials, API keys, or source code.

---

### 6.14 Visual OSINT Scanner
**What it does**: Captures screenshots and performs open-source intelligence gathering.

**What it captures**:
- **Full-page screenshots**: Visual record of the website
- **Favicon**: The site's icon
- **Visual changes**: Detect when the site appearance changes

**OSINT features** (with API keys configured):
- Google search results about the domain
- Social media mentions
- Data breach information

**Why it matters**: Screenshots provide visual evidence for reports and help track changes to websites over time.

---

### 6.15 Seed Files Scanner
**What it does**: Analyzes `robots.txt` and `sitemap.xml` files to discover site structure.

**What robots.txt reveals**:
- **Disallowed paths**: URLs the site doesn't want search engines to index
- **Allowed paths**: Explicitly permitted URLs
- **Sitemap locations**: Where to find XML sitemaps
- **Crawl delay**: How fast crawlers should access the site

**What sitemap.xml reveals**:
- **All public URLs**: Complete list of pages the site wants indexed
- **Last modification dates**: When pages were updated
- **Priority**: How important the site considers each page

**Why it matters**:
- Disallowed paths often hide sensitive areas (admin panels, internal tools)
- Sitemaps reveal the complete structure of the application
- Both files can expose paths you didn't know existed

**Example sensitive paths from robots.txt**:
```
Disallow: /admin/
Disallow: /internal/
Disallow: /backup/
Disallow: /api/debug/
```

---

### 6.16 CSP Scanner (Content Security Policy)
**What it does**: Analyzes the Content-Security-Policy header to discover external resources and evaluate security.

**What it extracts**:
- **External domains**: All third-party domains allowed by the CSP
- **Script sources**: Where JavaScript can be loaded from
- **Connection sources**: Where the site can make API calls
- **Frame sources**: What can be embedded in iframes

**Domain categorization**:
The scanner automatically categorizes discovered domains:
- **Potential company assets**: Domains that may belong to your organization (CDNs, APIs, staging)
- **CDN providers**: Cloudflare, Akamai, Fastly
- **Analytics**: Google Analytics, Mixpanel, Amplitude
- **Social media**: Facebook, Twitter, LinkedIn integrations
- **Advertising**: Ad networks and trackers
- **Payment processors**: Stripe, PayPal, Braintree
- **Cloud services**: AWS, Azure, GCP resources

**Security analysis**:
- **unsafe-inline**: Allows inline scripts (XSS risk)
- **unsafe-eval**: Allows eval() (code injection risk)
- **Wildcards**: Overly permissive sources
- **Missing directives**: Important protections not configured

**Why it matters**:
- CSP headers reveal your third-party dependencies
- External domains may be company assets you should add to your target list
- Security misconfigurations in CSP can enable cross-site scripting attacks

---

## 7. Report Builder

The Report Builder allows you to create custom, branded reports from your scan data. This is a powerful tool for generating executive summaries, compliance reports, and technical assessments.

### 7.1 Getting Started with Report Builder

1. Navigate to **Reports > Builder** in the sidebar
2. Choose a starting template or create from scratch
3. Select the targets to include in the report
4. Customize the content using variables
5. Preview and generate your report

### 7.2 Understanding Variables

Variables are placeholders that get replaced with actual data when the report is generated. They use the format `{{ variable.name }}`.

**Example**: If you write `{{ target.domain }}` in your template, it will be replaced with the actual domain name (e.g., `example.com`) when the report is generated.

### 7.3 Complete Variable Reference

#### Organization & Branding
These variables let you personalize reports with your company information:

| Variable | Description | Example Output |
|----------|-------------|----------------|
| `{{ tenant.name }}` | Your organization name | "Acme Corp" |
| `{{ tenant.report_company_name }}` | Company name for reports | "Acme Security Team" |
| `{{ tenant.report_logo_url }}` | Your logo URL | Image in header |
| `{{ tenant.report_primary_color }}` | Brand primary color | "#3b82f6" |
| `{{ tenant.report_header_text }}` | Custom header text | "Confidential" |
| `{{ tenant.report_footer_text }}` | Custom footer text | "Do Not Distribute" |

#### Report Metadata
Information about the report itself:

| Variable | Description | Example Output |
|----------|-------------|----------------|
| `{{ report.title }}` | Report title | "Security Assessment" |
| `{{ report.generated_at }}` | When report was created | "2026-01-26 14:30:00" |
| `{{ report.generated_at\|date }}` | Generation date only | "2026-01-26" |
| `{{ report.target_count }}` | Number of targets | "5" |
| `{{ now }}` | Current timestamp | Current date/time |
| `{{ now\|datetime }}` | Formatted current time | "2026-01-26 14:30:00" |

#### Summary Statistics
Aggregated data across all targets in the report:

| Variable | Description | Example Output |
|----------|-------------|----------------|
| `{{ summary.total_targets }}` | Total targets scanned | "10" |
| `{{ summary.total_vulnerabilities }}` | All vulnerabilities found | "47" |
| `{{ summary.critical_count }}` | Critical severity count | "2" |
| `{{ summary.high_count }}` | High severity count | "8" |
| `{{ summary.medium_count }}` | Medium severity count | "15" |
| `{{ summary.low_count }}` | Low severity count | "22" |
| `{{ summary.info_count }}` | Informational findings | "12" |

#### Target Information (Single-Target Reports)
When your report includes one target:

| Variable | Description | Example Output |
|----------|-------------|----------------|
| `{{ target.domain }}` | Domain name | "example.com" |
| `{{ target.id }}` | Internal ID | "42" |
| `{{ target.created_at }}` | When target was added | "2026-01-15" |
| `{{ target.tags }}` | List of tags | ["production", "critical"] |
| `{{ target.tags\|join(', ') }}` | Tags as text | "production, critical" |
| `{{ target.status }}` | Current status | "idle" |
| `{{ target.last_scan }}` | Last scan timestamp | "2026-01-26" |

#### DNS Data
Information from DNS scans:

| Variable | Description | Example Output |
|----------|-------------|----------------|
| `{{ dns.subdomains }}` | List of subdomains | List of subdomain objects |
| `{{ dns.subdomains\|count }}` | Number of subdomains | "23" |
| `{{ dns.records.A }}` | A records (IPv4) | ["93.184.216.34"] |
| `{{ dns.records.AAAA }}` | AAAA records (IPv6) | ["2606:2800:220:1::"] |
| `{{ dns.records.MX }}` | Mail server records | ["mail.example.com"] |
| `{{ dns.records.TXT }}` | Text records | ["v=spf1 ..."] |
| `{{ dns.records.NS }}` | Nameserver records | ["ns1.example.com"] |
| `{{ dns.records.CNAME }}` | Alias records | ["alias.example.com"] |
| `{{ dns.records.SPF }}` | SPF record | "v=spf1 include:..." |
| `{{ dns.records.DMARC }}` | DMARC record | "v=DMARC1; p=reject" |
| `{{ dns.nameservers }}` | Authoritative nameservers | ["ns1.example.com"] |
| `{{ dns.wildcard_detected }}` | Wildcard DNS enabled? | "True" or "False" |
| `{{ dns.dangling_cnames }}` | Vulnerable CNAME records | List of domains |

#### SSL/TLS Data
Certificate and encryption information:

| Variable | Description | Example Output |
|----------|-------------|----------------|
| `{{ ssl.issuer }}` | Certificate issuer (CA) | "Let's Encrypt Authority X3" |
| `{{ ssl.subject }}` | Certificate subject | "CN=example.com" |
| `{{ ssl.not_before }}` | Valid from date | "2026-01-01" |
| `{{ ssl.not_after }}` | Expiration date | "2026-04-01" |
| `{{ ssl.days_until_expiry }}` | Days until expiration | "64" |
| `{{ ssl.serial_number }}` | Certificate serial | "ABC123..." |
| `{{ ssl.subject_alt_names }}` | Alternative names | ["www.example.com"] |
| `{{ ssl.subject_alt_names\|count }}` | Number of SANs | "5" |
| `{{ ssl.signature_algorithm }}` | Signature algorithm | "SHA256withRSA" |
| `{{ ssl.public_key_type }}` | Key type | "RSA" |
| `{{ ssl.public_key_bits }}` | Key size | "2048" |
| `{{ ssl.ciphers }}` | Supported cipher suites | List of ciphers |
| `{{ ssl.protocols }}` | TLS/SSL protocols | ["TLSv1.2", "TLSv1.3"] |
| `{{ ssl.is_valid }}` | Certificate currently valid? | "True" |
| `{{ ssl.is_self_signed }}` | Self-signed certificate? | "False" |
| `{{ ssl.error }}` | Error message (if any) | "Connection refused" |

#### Web Analysis Data
Technology and security header information:

| Variable | Description | Example Output |
|----------|-------------|----------------|
| `{{ web.status_code }}` | HTTP response code | "200" |
| `{{ web.server }}` | Web server software | "nginx/1.18.0" |
| `{{ web.title }}` | Page title | "Welcome to Example" |
| `{{ web.tech_stack }}` | Detected technologies | ["WordPress", "PHP"] |
| `{{ web.tech_stack\|join(', ') }}` | Technologies as text | "WordPress, PHP, MySQL" |
| `{{ web.frameworks }}` | Web frameworks | ["React", "Bootstrap"] |
| `{{ web.cms }}` | Content management system | "WordPress" |
| `{{ web.security_headers }}` | Security headers object | See below |
| `{{ web.security_headers.X-Frame-Options }}` | X-Frame-Options header | "DENY" |
| `{{ web.security_headers.Strict-Transport-Security }}` | HSTS header | "max-age=31536000" |
| `{{ web.missing_headers }}` | Missing security headers | ["CSP", "X-XSS-Protection"] |
| `{{ web.has_login }}` | Login form detected? | "True" |
| `{{ web.cookies }}` | Cookies found | List of cookie objects |
| `{{ web.response_time_ms }}` | Response time (ms) | "245" |

#### Vulnerability Data (Nuclei Scanner)
Security findings and statistics:

| Variable | Description | Example Output |
|----------|-------------|----------------|
| `{{ nuclei.findings }}` | All vulnerability findings | List of vulnerabilities |
| `{{ nuclei.findings\|count }}` | Total finding count | "47" |
| `{{ nuclei.stats.critical }}` | Critical count | "2" |
| `{{ nuclei.stats.high }}` | High count | "8" |
| `{{ nuclei.stats.medium }}` | Medium count | "15" |
| `{{ nuclei.stats.low }}` | Low count | "22" |
| `{{ nuclei.stats.info }}` | Informational count | "12" |
| `{{ vulnerabilities }}` | Alias for findings | Same as nuclei.findings |

**Looping through vulnerabilities:**
```markdown
{% for v in nuclei.findings %}
- **{{ v.severity|upper }}**: {{ v.name }}
  - Template: {{ v.template_id }}
  - Description: {{ v.description }}
  - Found at: {{ v.matched_at }}
{% endfor %}
```

#### Nmap / Port Scan Data
Network port information:

| Variable | Description | Example Output |
|----------|-------------|----------------|
| `{{ nmap.open_ports }}` | List of open ports | List of port objects |
| `{{ nmap.open_ports\|count }}` | Number of open ports | "12" |
| `{{ nmap.services }}` | Detected services | ["SSH", "HTTP", "MySQL"] |
| `{{ nmap.os_detection }}` | Operating system guess | "Linux 4.15" |
| `{{ nmap.host_status }}` | Host up/down | "up" |

**Looping through ports:**
```markdown
{% for p in nmap.open_ports %}
| {{ p.port }} | {{ p.protocol }} | {{ p.service }} | {{ p.version }} |
{% endfor %}
```

#### Infrastructure Data
Hosting and network information:

| Variable | Description | Example Output |
|----------|-------------|----------------|
| `{{ infrastructure.ip_address }}` | Primary IP address | "93.184.216.34" |
| `{{ infrastructure.asn }}` | AS Number | "AS15133" |
| `{{ infrastructure.asn_org }}` | ASN organization | "EdgeCast Networks" |
| `{{ infrastructure.isp }}` | Internet service provider | "Verizon Digital Media" |
| `{{ infrastructure.country }}` | Server country | "United States" |
| `{{ infrastructure.city }}` | Server city | "Los Angeles" |
| `{{ infrastructure.region }}` | Server region | "California" |
| `{{ infrastructure.hosting_provider }}` | Hosting provider | "AWS" |
| `{{ infrastructure.is_cloud }}` | Hosted on cloud? | "True" |
| `{{ infrastructure.cloud_provider }}` | Cloud provider name | "Amazon Web Services" |
| `{{ infrastructure.reverse_dns }}` | PTR record | "server1.example.com" |

#### Cloud Scanner Data
Cloud storage findings:

| Variable | Description | Example Output |
|----------|-------------|----------------|
| `{{ cloud.buckets }}` | Discovered buckets | List of bucket objects |
| `{{ cloud.buckets\|count }}` | Number of buckets | "3" |
| `{{ cloud.public_buckets }}` | Publicly accessible | List of public buckets |

**Looping through buckets:**
```markdown
{% for b in cloud.buckets %}
- **{{ b.name }}** ({{ b.provider }}) - {{ 'PUBLIC' if b.is_public else 'Private' }}
{% endfor %}
```

#### Typosquatting Data
Lookalike domain findings:

| Variable | Description | Example Output |
|----------|-------------|----------------|
| `{{ typosquat.lookalikes }}` | All lookalike domains | List of domain objects |
| `{{ typosquat.lookalikes\|count }}` | Number found | "15" |
| `{{ typosquat.registered }}` | Registered lookalikes | Domains that exist |
| `{{ typosquat.available }}` | Available domains | Domains not registered |
| `{{ typosquat.risky }}` | High-risk lookalikes | Active phishing sites |

#### Crawler Data
Web spidering results:

| Variable | Description | Example Output |
|----------|-------------|----------------|
| `{{ crawler.pages }}` | Crawled pages | List of URLs |
| `{{ crawler.pages\|count }}` | Number of pages | "156" |
| `{{ crawler.internal_links }}` | Internal links found | List of links |
| `{{ crawler.external_links }}` | External links found | List of links |
| `{{ crawler.forms }}` | Forms discovered | List of form objects |
| `{{ crawler.emails }}` | Email addresses found | ["contact@example.com"] |
| `{{ crawler.files }}` | Files discovered | ["/docs/manual.pdf"] |
| `{{ crawler.js_files }}` | JavaScript files | List of JS URLs |
| `{{ crawler.api_endpoints }}` | Potential API paths | ["/api/v1/users"] |

#### Wayback Machine Data
Historical archive information:

| Variable | Description | Example Output |
|----------|-------------|----------------|
| `{{ wayback.snapshots }}` | Archive snapshots | List of snapshot objects |
| `{{ wayback.snapshots\|count }}` | Number of snapshots | "847" |
| `{{ wayback.first_seen }}` | First archive date | "2005-03-15" |
| `{{ wayback.last_seen }}` | Most recent archive | "2026-01-20" |
| `{{ wayback.historical_urls }}` | Old URLs discovered | List of historical URLs |

#### Seed Files Data (robots.txt & sitemap.xml)
Site structure information:

| Variable | Description | Example Output |
|----------|-------------|----------------|
| `{{ seed_files.robots_txt.found }}` | robots.txt exists? | "True" |
| `{{ seed_files.robots_txt.disallow_rules }}` | Disallowed paths | ["/admin", "/backup"] |
| `{{ seed_files.robots_txt.allow_rules }}` | Allowed paths | ["/public"] |
| `{{ seed_files.robots_txt.sitemaps }}` | Declared sitemaps | ["/sitemap.xml"] |
| `{{ seed_files.robots_txt.crawl_delay }}` | Crawl delay value | "10" |
| `{{ seed_files.sitemaps }}` | Analyzed sitemaps | List of sitemap objects |
| `{{ seed_files.sitemaps\|count }}` | Number of sitemaps | "3" |
| `{{ seed_files.total_urls }}` | Total URLs in sitemaps | "1523" |
| `{{ seed_files.sensitive_paths }}` | Sensitive paths found | ["/backup", "/config"] |
| `{{ seed_files.statistics.total_paths }}` | Total paths discovered | "234" |

#### CSP Scanner Data
Content Security Policy analysis:

| Variable | Description | Example Output |
|----------|-------------|----------------|
| `{{ csp.csp_header }}` | Full CSP header | "default-src 'self'..." |
| `{{ csp.has_csp }}` | CSP header present? | "True" |
| `{{ csp.csp_report_only }}` | Report-Only CSP | CSP header (if exists) |
| `{{ csp.external_domains }}` | All external domains | List of domains |
| `{{ csp.external_domains\|count }}` | External domain count | "23" |
| `{{ csp.potential_assets }}` | Potential company assets | List of asset objects |
| `{{ csp.third_party_services }}` | Third-party by category | Dict of categories |
| `{{ csp.third_party_services.cdn }}` | CDN domains | ["cdn.example.com"] |
| `{{ csp.third_party_services.analytics }}` | Analytics domains | ["analytics.google.com"] |
| `{{ csp.third_party_services.social }}` | Social media domains | ["facebook.com"] |
| `{{ csp.third_party_services.payment }}` | Payment processors | ["stripe.com"] |
| `{{ csp.security_findings }}` | CSP security issues | List of findings |
| `{{ csp.parsed_directives }}` | Parsed CSP directives | Dict of directives |
| `{{ csp.statistics.security_issues }}` | Number of CSP issues | "3" |

**Looping through CSP assets:**
```markdown
{% for a in csp.potential_assets %}
- **{{ a.domain }}** - {{ a.reason }} (Priority: {{ a.priority }})
{% endfor %}
```

### 7.4 Filters and Formatting

Filters transform data when displayed. Add them after a variable using the pipe `|` character.

| Filter | Description | Example |
|--------|-------------|---------|
| `\|date` | Format as date | `{{ ssl.not_after\|date }}` → "2026-04-01" |
| `\|datetime` | Format as date and time | `{{ now\|datetime }}` → "2026-01-26 14:30:00" |
| `\|count` | Count items in a list | `{{ dns.subdomains\|count }}` → "23" |
| `\|truncate(50)` | Shorten text to length | `{{ description\|truncate(50) }}` → "This is a long..." |
| `\|severity_badge` | Colored severity badge | `{{ v.severity\|severity_badge }}` → HTML badge |
| `\|join(', ')` | Join list with separator | `{{ tags\|join(', ') }}` → "prod, critical" |
| `\|default('N/A')` | Default if empty | `{{ server\|default('Unknown') }}` → "Unknown" |
| `\|upper` | Convert to UPPERCASE | `{{ severity\|upper }}` → "HIGH" |
| `\|lower` | Convert to lowercase | `{{ status\|lower }}` → "active" |

### 7.5 Conditionals

Use conditionals to show content only when certain conditions are met.

**Basic if statement:**
```markdown
{% if ssl.is_valid %}
Certificate is valid and will expire in {{ ssl.days_until_expiry }} days.
{% else %}
**WARNING**: Certificate is invalid or expired!
{% endif %}
```

**Checking if data exists:**
```markdown
{% if nuclei.findings|count > 0 %}
## Vulnerabilities Found
{% for v in nuclei.findings %}
- {{ v.name }} ({{ v.severity }})
{% endfor %}
{% else %}
No vulnerabilities detected.
{% endif %}
```

### 7.6 Multi-Target Reports

For reports covering multiple targets, use loops:

```markdown
# Security Assessment

{% for t in targets %}
## {{ t.domain }}

**Status:** {{ t.status }}
**Added:** {{ t.created_at|date }}

### Vulnerabilities
{% if t.modules.nuclei_scanner %}
{% for v in t.modules.nuclei_scanner.vulnerabilities %}
- {{ v.severity|upper }}: {{ v.name }}
{% endfor %}
{% else %}
No vulnerability scan data available.
{% endif %}

---
{% endfor %}
```

### 7.7 Example Templates

**Executive Summary Template:**
```markdown
# Executive Security Summary

**Organization:** {{ tenant.report_company_name }}
**Date:** {{ now|date }}
**Scope:** {{ report.target_count }} target(s)

## Key Findings

| Severity | Count |
|----------|-------|
| Critical | {{ summary.critical_count }} |
| High | {{ summary.high_count }} |
| Medium | {{ summary.medium_count }} |
| Low | {{ summary.low_count }} |

{% if summary.critical_count > 0 %}
**Action Required:** Critical vulnerabilities require immediate attention.
{% endif %}

## Recommendations

1. Address all critical findings within 24 hours
2. Remediate high-severity issues within 7 days
3. Review medium issues in the next sprint
```

**SSL Certificate Report Template:**
```markdown
# SSL Certificate Status Report

**Generated:** {{ now|datetime }}

{% for t in targets %}
## {{ t.domain }}

{% if t.modules.ssl_scanner %}
| Property | Value |
|----------|-------|
| Issuer | {{ t.modules.ssl_scanner.issuer|default('N/A') }} |
| Expires | {{ t.modules.ssl_scanner.not_after|default('N/A') }} |
| Days Left | {{ t.modules.ssl_scanner.days_until_expiry|default('Unknown') }} |

{% if t.modules.ssl_scanner.days_until_expiry and t.modules.ssl_scanner.days_until_expiry < 30 %}
**WARNING:** Certificate expires soon!
{% endif %}
{% else %}
*No SSL data available*
{% endif %}

---
{% endfor %}
```

### 7.8 Data Isolation

**Important:** All report data is automatically filtered by your tenant. You can only access data belonging to your organization. This ensures:
- You never accidentally see another tenant's data
- Reports only include targets assigned to your tenant
- All variables automatically respect tenant boundaries

---

## 8. OSINT Brand Monitoring

The OSINT module helps you discover unmonitored assets by finding where your brand assets (logos) appear on the web.

### Prerequisites
Configure the **Google Cloud Vision API** in Tenant Settings:
1. Enable the **Cloud Vision API** in Google Cloud Console
2. Create an API Key in "Credentials"
3. Link an active Billing Account

### Using Reverse Image Search
1. Upload your official logo (PNG/JPG)
2. The system searches for matches across the web
3. Review discovered domains and import relevant ones

---

## 9. Visualizations

### Network Graph
Interactive visualization showing relationships between domains, IPs, and networks.

### Analytics Dashboard
High-level metrics including world map, technology distribution, and risk overview.

### Compliance Grading
Security grade (A-F) based on SSL, headers, vulnerabilities, and open ports.

---

## 10. Data Management & Reports

### Available Reports
- **Infrastructure Executive Summary**: Professional PDF with cloud providers, geographic distribution, and risks
- **Compliance Report**: SOC2 readiness score with improvement checklist
- **External Links Report**: Third-party domains linked to your infrastructure

### Data Exports
- **Target CSV**: Raw target inventory
- **Excel Export**: Full data with all columns
- **Backup**: Complete database and assets as ZIP

---

## 11. User Management & Security

### Roles
- **Viewer**: Read-only access
- **Scanner**: Can add targets and run scans
- **Admin**: Full system access

### Multi-Factor Authentication
Users can enable 2FA in their profile using any TOTP authenticator app.

---

## 12. Multi-Tenancy

YADS supports multiple isolated environments (Tenants).

- **Isolation**: Targets, Results, and Users are scoped to a Tenant
- **Switching**: Users with multiple tenants can switch via the dropdown
- **Platform Admin**: Admin without a tenant sees everything

---

## 13. System Settings & Queue

### Queue Control
- **Pause/Resume**: Stop/start the background worker
- **Clear Queue**: Cancel all pending scans
- **System Reset**: Revert to clean state

### Worker Management
Monitor and configure distributed workers, assign workers to specific tenants.

---

## 14. API Keys Configuration

Several scanner features require API keys for enhanced functionality.

### Nuclei API Key (Optional)
Enables cloud-based vulnerability templates.
- Get it at: [cloud.projectdiscovery.io](https://cloud.projectdiscovery.io)

### Have I Been Pwned (HIBP) API Key
Enables data breach checking.
- Get it at: [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key)

### Hunter.io API Key
Enables email discovery features.
- Get it at: [hunter.io/api](https://hunter.io/api)

### GitHub API Token
Enables GitHub repository scanning.
- Create at: [github.com/settings/tokens](https://github.com/settings/tokens)

### Shodan API Key
Enables internet-wide device search.
- Get it at: [account.shodan.io](https://account.shodan.io)

### Censys API Keys
Enables certificate and host search.
- Get it at: [search.censys.io/account/api](https://search.censys.io/account/api)

### VirusTotal API Key
Enables malware and URL scanning.
- Get it at: [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey)

---

## 15. Best Practices

1. **Tagging**: Use tags creatively (`prod`, `dev`, `critical`) to organize targets
2. **Regular Reviews**: Check Analytics weekly to spot trends
3. **Scope Definition**: Be careful with root domains - subdomain discovery can find hundreds of assets
4. **Scheduled Scans**: Set up weekly scans for continuous monitoring
5. **Report Templates**: Create templates for recurring reports

---

## 16. Troubleshooting

### Scan stuck in "Pending"
- Check **Settings > Queue Control** - ensure queue is active
- Verify worker is running

### "Web Analyzer" failed
- Target might be offline or blocking the scanner
- Try increasing **Web Request Timeout** in settings

### MFA Code Rejected
- Ensure server time is synced via NTP
- Try waiting for the next code

### No data appearing
- Verify scans have completed (check target status)
- Ensure you're viewing the correct tenant

---

## Support

For technical support or to report bugs: info@yads-security.com

---

*Verified for YADS v1.17.0*

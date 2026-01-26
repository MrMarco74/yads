# YADS Report Builder - Complete Guide

**Version:** 1.17.0
**Last Updated:** 2026-01-26

The Report Builder allows you to create custom, branded security reports from your scan data. This guide covers everything from basic usage to advanced template customization.

---

## Table of Contents

1. [Getting Started](#1-getting-started)
2. [Understanding Variables](#2-understanding-variables)
3. [Complete Variable Reference](#3-complete-variable-reference)
4. [Filters and Formatting](#4-filters-and-formatting)
5. [Conditionals](#5-conditionals)
6. [Loops and Multi-Target Reports](#6-loops-and-multi-target-reports)
7. [Example Templates](#7-example-templates)
8. [Data Isolation and Security](#8-data-isolation-and-security)
9. [Tips and Best Practices](#9-tips-and-best-practices)

---

## 1. Getting Started

### Accessing the Report Builder

1. Navigate to **Reports > Builder** in the sidebar
2. You'll see a list of available templates (system and custom)
3. Click **"Create Template"** to start from scratch, or select an existing template to modify

### Basic Workflow

1. **Choose a Template**: Start with a system template or create your own
2. **Select Targets**: Choose which domains to include in the report
3. **Customize Content**: Edit the markdown template with variables
4. **Preview**: See how your report will look with real data
5. **Generate**: Create the final report (HTML or PDF)

### Template Editor Interface

The editor shows:
- **Left Panel**: Markdown editor with syntax highlighting
- **Right Panel**: Live preview with your data
- **Top Bar**: Template name, save button, and settings
- **Bottom Panel**: Available variables reference

---

## 2. Understanding Variables

Variables are placeholders in your template that get replaced with actual data when the report is generated.

### Variable Syntax

Variables use double curly braces: `{{ variable.name }}`

**Example:**
```markdown
# Security Report for {{ target.domain }}
Generated on {{ now|date }}
```

**Becomes:**
```markdown
# Security Report for example.com
Generated on 2026-01-26
```

### Variable Types

| Type | Example | Description |
|------|---------|-------------|
| **Simple** | `{{ target.domain }}` | Single value (text, number) |
| **Object** | `{{ ssl.issuer }}` | Property of an object |
| **List** | `{{ dns.subdomains }}` | Array of items |
| **Nested** | `{{ web.security_headers.HSTS }}` | Deeply nested property |

---

## 3. Complete Variable Reference

### 3.1 Organization & Branding

Personalize reports with your company information:

| Variable | Description | Example Output |
|----------|-------------|----------------|
| `{{ tenant.name }}` | Organization name | "Acme Corp" |
| `{{ tenant.report_company_name }}` | Company name for reports | "Acme Security Team" |
| `{{ tenant.report_logo_url }}` | Logo URL or data URI | Used in header |
| `{{ tenant.report_primary_color }}` | Primary brand color (hex) | "#3b82f6" |
| `{{ tenant.report_secondary_color }}` | Secondary brand color | "#64748b" |
| `{{ tenant.report_header_text }}` | Custom header text | "Confidential" |
| `{{ tenant.report_footer_text }}` | Custom footer text | "Internal Use Only" |

### 3.2 Report Metadata

| Variable | Description | Example Output |
|----------|-------------|----------------|
| `{{ report.title }}` | Report title | "Security Assessment" |
| `{{ report.generated_at }}` | Generation timestamp | "2026-01-26 14:30:00" |
| `{{ report.generated_at\|date }}` | Generation date only | "2026-01-26" |
| `{{ report.target_count }}` | Number of targets | "5" |
| `{{ now }}` | Current timestamp | Current date/time |
| `{{ now\|datetime }}` | Formatted current time | "2026-01-26 14:30:00" |

### 3.3 Summary Statistics

Aggregated data across all targets:

| Variable | Description | Example Output |
|----------|-------------|----------------|
| `{{ summary.total_targets }}` | Total targets scanned | "10" |
| `{{ summary.total_vulnerabilities }}` | All vulnerabilities found | "47" |
| `{{ summary.critical_count }}` | Critical severity count | "2" |
| `{{ summary.high_count }}` | High severity count | "8" |
| `{{ summary.medium_count }}` | Medium severity count | "15" |
| `{{ summary.low_count }}` | Low severity count | "22" |
| `{{ summary.info_count }}` | Informational findings | "12" |

### 3.4 Target Information

For single-target reports:

| Variable | Description | Example Output |
|----------|-------------|----------------|
| `{{ target.domain }}` | Domain name | "example.com" |
| `{{ target.id }}` | Internal ID | "42" |
| `{{ target.created_at }}` | When target was added | "2026-01-15" |
| `{{ target.tags }}` | List of tags | ["production", "critical"] |
| `{{ target.tags\|join(', ') }}` | Tags as text | "production, critical" |
| `{{ target.status }}` | Current status | "idle" |
| `{{ target.last_scan }}` | Last scan timestamp | "2026-01-26" |

### 3.5 DNS Scanner Data

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
| `{{ dns.records.SOA }}` | SOA record | SOA data object |
| `{{ dns.records.SPF }}` | SPF record | "v=spf1 include:..." |
| `{{ dns.records.DMARC }}` | DMARC record | "v=DMARC1; p=reject" |
| `{{ dns.records.DKIM }}` | DKIM records | List of DKIM records |
| `{{ dns.nameservers }}` | Authoritative nameservers | ["ns1.example.com"] |
| `{{ dns.wildcard_detected }}` | Wildcard DNS enabled? | "True" or "False" |
| `{{ dns.dangling_cnames }}` | Vulnerable CNAME records | List of domains |
| `{{ dns.zone_transfer_possible }}` | Zone transfer allowed? | "False" |

### 3.6 SSL/TLS Scanner Data

| Variable | Description | Example Output |
|----------|-------------|----------------|
| `{{ ssl.issuer }}` | Certificate issuer (CA) | "Let's Encrypt Authority X3" |
| `{{ ssl.subject }}` | Certificate subject | "CN=example.com" |
| `{{ ssl.not_before }}` | Valid from date | "2026-01-01" |
| `{{ ssl.not_after }}` | Expiration date | "2026-04-01" |
| `{{ ssl.days_until_expiry }}` | Days until expiration | "64" |
| `{{ ssl.serial_number }}` | Certificate serial | "ABC123..." |
| `{{ ssl.version }}` | Certificate version | "3" |
| `{{ ssl.subject_alt_names }}` | Alternative names | ["www.example.com"] |
| `{{ ssl.subject_alt_names\|count }}` | Number of SANs | "5" |
| `{{ ssl.signature_algorithm }}` | Signature algorithm | "SHA256withRSA" |
| `{{ ssl.public_key_type }}` | Key type | "RSA" |
| `{{ ssl.public_key_bits }}` | Key size | "2048" |
| `{{ ssl.ciphers }}` | Supported cipher suites | List of ciphers |
| `{{ ssl.protocols }}` | TLS/SSL protocols | ["TLSv1.2", "TLSv1.3"] |
| `{{ ssl.is_valid }}` | Certificate currently valid? | "True" |
| `{{ ssl.is_self_signed }}` | Self-signed certificate? | "False" |
| `{{ ssl.chain }}` | Certificate chain details | Chain data object |
| `{{ ssl.error }}` | Error message (if any) | "Connection refused" |

### 3.7 Web Analyzer Data

| Variable | Description | Example Output |
|----------|-------------|----------------|
| `{{ web.status_code }}` | HTTP response code | "200" |
| `{{ web.server }}` | Web server software | "nginx/1.18.0" |
| `{{ web.title }}` | Page title | "Welcome to Example" |
| `{{ web.tech_stack }}` | Detected technologies | ["WordPress", "PHP"] |
| `{{ web.tech_stack\|join(', ') }}` | Technologies as text | "WordPress, PHP, MySQL" |
| `{{ web.frameworks }}` | Web frameworks | ["React", "Bootstrap"] |
| `{{ web.cms }}` | Content management system | "WordPress" |
| `{{ web.programming_languages }}` | Detected languages | ["PHP", "JavaScript"] |
| `{{ web.security_headers }}` | Security headers object | Dict of headers |
| `{{ web.security_headers.X-Frame-Options }}` | X-Frame-Options header | "DENY" |
| `{{ web.security_headers.Content-Security-Policy }}` | CSP header | CSP value |
| `{{ web.security_headers.Strict-Transport-Security }}` | HSTS header | "max-age=31536000" |
| `{{ web.security_headers.X-Content-Type-Options }}` | X-Content-Type-Options | "nosniff" |
| `{{ web.missing_headers }}` | Missing security headers | ["CSP", "X-XSS-Protection"] |
| `{{ web.cookies }}` | Cookies found | List of cookie objects |
| `{{ web.has_login }}` | Login form detected? | "True" |
| `{{ web.forms }}` | Forms found on page | List of form objects |
| `{{ web.external_links }}` | External links found | List of URLs |
| `{{ web.meta_tags }}` | HTML meta tags | Dict of meta tags |
| `{{ web.response_time_ms }}` | Response time (ms) | "245" |

### 3.8 Vulnerability Scanner (Nuclei) Data

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

**Individual vulnerability properties:**
| Property | Description |
|----------|-------------|
| `v.name` | Vulnerability name |
| `v.severity` | Severity level |
| `v.template_id` | Nuclei template ID |
| `v.description` | Detailed description |
| `v.matched_at` | URL where found |
| `v.curl_command` | cURL to reproduce |
| `v.reference` | Reference links |
| `v.remediation` | Fix guidance |
| `v.cve_id` | CVE identifier |

### 3.9 Nmap / Port Scanner Data

| Variable | Description | Example Output |
|----------|-------------|----------------|
| `{{ nmap.open_ports }}` | List of open ports | List of port objects |
| `{{ nmap.open_ports\|count }}` | Number of open ports | "12" |
| `{{ nmap.services }}` | Detected services | ["SSH", "HTTP", "MySQL"] |
| `{{ nmap.os_detection }}` | Operating system guess | "Linux 4.15" |
| `{{ nmap.host_status }}` | Host up/down | "up" |
| `{{ nmap.scan_time }}` | Scan duration | "45.2s" |

**Individual port properties:**
| Property | Description |
|----------|-------------|
| `p.port` | Port number |
| `p.protocol` | Protocol (tcp/udp) |
| `p.service` | Service name |
| `p.version` | Service version |
| `p.state` | Port state (open/closed) |

### 3.10 Infrastructure Scanner Data

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
| `{{ infrastructure.datacenter }}` | Datacenter info | "us-east-1" |
| `{{ infrastructure.reverse_dns }}` | PTR record | "server1.example.com" |

### 3.11 Cloud Scanner Data

| Variable | Description | Example Output |
|----------|-------------|----------------|
| `{{ cloud.buckets }}` | Discovered buckets | List of bucket objects |
| `{{ cloud.buckets\|count }}` | Number of buckets | "3" |
| `{{ cloud.public_buckets }}` | Publicly accessible buckets | List of public buckets |
| `{{ cloud.azure_blobs }}` | Azure blob containers | List of containers |
| `{{ cloud.gcp_buckets }}` | Google Cloud Storage buckets | List of buckets |

**Individual bucket properties:**
| Property | Description |
|----------|-------------|
| `b.name` | Bucket name |
| `b.provider` | Cloud provider (S3, Azure, GCP) |
| `b.region` | Bucket region |
| `b.is_public` | Publicly accessible? |
| `b.url` | Bucket URL |

### 3.12 Typosquatting Scanner Data

| Variable | Description | Example Output |
|----------|-------------|----------------|
| `{{ typosquat.lookalikes }}` | All lookalike domains | List of domain objects |
| `{{ typosquat.lookalikes\|count }}` | Number found | "15" |
| `{{ typosquat.registered }}` | Registered lookalikes | Domains that exist |
| `{{ typosquat.available }}` | Available domains | Domains not registered |
| `{{ typosquat.risky }}` | High-risk lookalikes | Active phishing sites |
| `{{ typosquat.brand_impersonation }}` | Brand impersonation domains | List of domains |

**Individual lookalike properties:**
| Property | Description |
|----------|-------------|
| `d.domain` | Lookalike domain name |
| `d.technique` | Typosquat technique used |
| `d.is_registered` | Domain registered? |
| `d.is_active` | Has active website? |
| `d.similarity_score` | Visual similarity (0-100) |
| `d.risk_level` | Risk assessment |

### 3.13 Visual OSINT Data

| Variable | Description | Example Output |
|----------|-------------|----------------|
| `{{ osint.screenshots }}` | List of screenshots | List of screenshot objects |
| `{{ osint.screenshots\|count }}` | Number of screenshots | "3" |
| `{{ osint.google_results }}` | Google search results | List of results |
| `{{ osint.social_media }}` | Social media mentions | List of mentions |
| `{{ osint.breach_data }}` | Data breach info | Breach data object |
| `{{ osint.paste_sites }}` | Paste site mentions | List of pastes |
| `{{ osint.metadata }}` | Extracted metadata | Metadata object |

### 3.14 Crawler Data

| Variable | Description | Example Output |
|----------|-------------|----------------|
| `{{ crawler.pages }}` | Crawled pages | List of URLs |
| `{{ crawler.pages\|count }}` | Number of pages | "156" |
| `{{ crawler.internal_links }}` | Internal links found | List of links |
| `{{ crawler.external_links }}` | External links found | List of links |
| `{{ crawler.forms }}` | Forms discovered | List of form objects |
| `{{ crawler.emails }}` | Email addresses found | ["contact@example.com"] |
| `{{ crawler.files }}` | Files discovered | ["/docs/manual.pdf"] |
| `{{ crawler.parameters }}` | URL parameters found | List of parameters |
| `{{ crawler.comments }}` | HTML comments | List of comments |
| `{{ crawler.js_files }}` | JavaScript files | List of JS URLs |
| `{{ crawler.api_endpoints }}` | Potential API paths | ["/api/v1/users"] |

### 3.15 Wayback Machine Data

| Variable | Description | Example Output |
|----------|-------------|----------------|
| `{{ wayback.snapshots }}` | Archive snapshots | List of snapshot objects |
| `{{ wayback.snapshots\|count }}` | Number of snapshots | "847" |
| `{{ wayback.first_seen }}` | First archive date | "2005-03-15" |
| `{{ wayback.last_seen }}` | Most recent archive | "2026-01-20" |
| `{{ wayback.historical_urls }}` | Old URLs discovered | List of historical URLs |
| `{{ wayback.removed_pages }}` | Pages no longer available | List of URLs |
| `{{ wayback.old_technologies }}` | Historical tech stack | List of technologies |

### 3.16 TLD Scanner Data

| Variable | Description | Example Output |
|----------|-------------|----------------|
| `{{ tld.variations }}` | Domain TLD variations | List of domain objects |
| `{{ tld.registered }}` | Registered TLD variations | List of domains |
| `{{ tld.available }}` | Available TLD variations | List of domains |
| `{{ tld.parked }}` | Parked domains | List of domains |
| `{{ tld.active_sites }}` | TLDs with active sites | List of domains |

### 3.17 Content Discovery Data

| Variable | Description | Example Output |
|----------|-------------|----------------|
| `{{ content_discovery.directories }}` | Discovered directories | List of paths |
| `{{ content_discovery.files }}` | Discovered files | List of files |
| `{{ content_discovery.backup_files }}` | Backup files found | ["/backup.zip"] |
| `{{ content_discovery.config_files }}` | Config files found | ["/.env"] |
| `{{ content_discovery.admin_panels }}` | Admin panel URLs | ["/admin"] |
| `{{ content_discovery.sensitive_paths }}` | Sensitive paths found | List of paths |

### 3.18 Seed Files Scanner Data (robots.txt & sitemap.xml)

| Variable | Description | Example Output |
|----------|-------------|----------------|
| `{{ seed_files.robots_txt }}` | robots.txt analysis | Object with analysis |
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
| `{{ seed_files.statistics.sensitive_paths_count }}` | Sensitive path count | "12" |

**Individual sitemap properties:**
| Property | Description |
|----------|-------------|
| `sm.url` | Sitemap URL |
| `sm.url_count` | Number of URLs |
| `sm.lastmod` | Last modification |

### 3.19 CSP Scanner Data (Content Security Policy)

| Variable | Description | Example Output |
|----------|-------------|----------------|
| `{{ csp.csp_header }}` | Full CSP header | "default-src 'self'..." |
| `{{ csp.has_csp }}` | CSP header present? | "True" |
| `{{ csp.csp_report_only }}` | Report-Only CSP | CSP header value |
| `{{ csp.external_domains }}` | All external domains | List of domains |
| `{{ csp.external_domains\|count }}` | External domain count | "23" |
| `{{ csp.potential_assets }}` | Potential company assets | List of asset objects |
| `{{ csp.third_party_services }}` | Third-party by category | Dict of categories |
| `{{ csp.third_party_services.cdn }}` | CDN domains | ["cdn.example.com"] |
| `{{ csp.third_party_services.analytics }}` | Analytics domains | ["analytics.google.com"] |
| `{{ csp.third_party_services.social }}` | Social media domains | ["facebook.com"] |
| `{{ csp.third_party_services.advertising }}` | Advertising domains | ["doubleclick.net"] |
| `{{ csp.third_party_services.payment }}` | Payment processors | ["stripe.com"] |
| `{{ csp.third_party_services.support }}` | Support/chat domains | ["intercom.io"] |
| `{{ csp.third_party_services.cloud }}` | Cloud service domains | ["amazonaws.com"] |
| `{{ csp.third_party_services.monitoring }}` | Monitoring domains | ["sentry.io"] |
| `{{ csp.security_findings }}` | CSP security issues | List of findings |
| `{{ csp.parsed_directives }}` | Parsed CSP directives | Dict of directives |
| `{{ csp.statistics.security_issues }}` | Number of CSP issues | "3" |
| `{{ csp.statistics.total_external_domains }}` | Total external domains | "23" |
| `{{ csp.statistics.potential_company_assets }}` | Company asset count | "5" |

**Individual potential asset properties:**
| Property | Description |
|----------|-------------|
| `a.domain` | Asset domain |
| `a.reason` | Why it's a potential asset |
| `a.priority` | Priority level (high/medium/low) |

---

## 4. Filters and Formatting

Filters transform data when displayed. Add them after a variable using the pipe `|` character.

### Available Filters

| Filter | Description | Example |
|--------|-------------|---------|
| `\|date` | Format as date (YYYY-MM-DD) | `{{ ssl.not_after\|date }}` |
| `\|datetime` | Format as date and time | `{{ now\|datetime }}` |
| `\|count` | Count items in a list | `{{ dns.subdomains\|count }}` |
| `\|truncate(50)` | Shorten text to length | `{{ description\|truncate(50) }}` |
| `\|severity_badge` | Render as colored badge | `{{ v.severity\|severity_badge }}` |
| `\|join(', ')` | Join list with separator | `{{ tags\|join(', ') }}` |
| `\|default('N/A')` | Default value if empty | `{{ server\|default('Unknown') }}` |
| `\|upper` | Convert to UPPERCASE | `{{ severity\|upper }}` |
| `\|lower` | Convert to lowercase | `{{ status\|lower }}` |

### Filter Examples

```markdown
<!-- Format dates -->
Certificate expires: {{ ssl.not_after|date }}

<!-- Count items -->
Found {{ dns.subdomains|count }} subdomains

<!-- Join lists -->
Tags: {{ target.tags|join(', ') }}

<!-- Provide defaults -->
Server: {{ web.server|default('Not disclosed') }}

<!-- Truncate long text -->
{{ vuln.description|truncate(100) }}

<!-- Chain filters -->
{{ severity|upper|default('UNKNOWN') }}
```

---

## 5. Conditionals

Use conditionals to show content only when certain conditions are met.

### Basic If Statement

```markdown
{% if ssl.is_valid %}
Certificate is valid and will expire in {{ ssl.days_until_expiry }} days.
{% endif %}
```

### If-Else Statement

```markdown
{% if summary.critical_count > 0 %}
**CRITICAL**: Immediate action required!
{% else %}
No critical vulnerabilities found.
{% endif %}
```

### Checking if Data Exists

```markdown
{% if nuclei.findings %}
## Vulnerabilities Found
{% for v in nuclei.findings %}
- {{ v.name }} ({{ v.severity }})
{% endfor %}
{% else %}
No vulnerabilities detected.
{% endif %}
```

### Complex Conditions

```markdown
{% if summary.critical_count > 0 or summary.high_count > 5 %}
**HIGH RISK**: This infrastructure requires immediate attention.
{% elif summary.medium_count > 10 %}
**MODERATE RISK**: Schedule remediation in the next sprint.
{% else %}
**LOW RISK**: Continue regular monitoring.
{% endif %}
```

### Checking List Length

```markdown
{% if dns.subdomains|count > 0 %}
### Subdomains ({{ dns.subdomains|count }} found)
{% endif %}
```

---

## 6. Loops and Multi-Target Reports

### Basic Loop

```markdown
{% for subdomain in dns.subdomains %}
- {{ subdomain.subdomain }} ({{ subdomain.ips|join(', ') }})
{% endfor %}
```

### Loop with Index

```markdown
{% for v in nuclei.findings %}
{{ loop.index }}. {{ v.name }} - {{ v.severity|upper }}
{% endfor %}
```

### Multi-Target Reports

For reports covering multiple targets:

```markdown
# Security Assessment

{% for t in targets %}
## {{ loop.index }}. {{ t.domain }}

**Status:** {{ t.status }}
**Added:** {{ t.created_at|date }}
**Tags:** {{ t.tags|join(', ')|default('None') }}

### DNS Records
{% if t.modules.dns_scanner %}
- **A Records:** {{ t.modules.dns_scanner.records.A|join(', ')|default('None') }}
- **MX Records:** {{ t.modules.dns_scanner.records.MX|join(', ')|default('None') }}
- **Subdomains:** {{ t.modules.dns_scanner.subdomains|count }} found
{% else %}
*No DNS scan data available*
{% endif %}

### SSL Certificate
{% if t.modules.ssl_scanner %}
- **Issuer:** {{ t.modules.ssl_scanner.issuer|default('N/A') }}
- **Expires:** {{ t.modules.ssl_scanner.not_after|default('N/A') }}
{% else %}
*No SSL scan data available*
{% endif %}

### Vulnerabilities
{% if t.modules.nuclei_scanner and t.modules.nuclei_scanner.vulnerabilities %}
| Severity | Name | Template |
|----------|------|----------|
{% for v in t.modules.nuclei_scanner.vulnerabilities %}
| {{ v.severity|upper }} | {{ v.name }} | {{ v.template_id }} |
{% endfor %}
{% else %}
*No vulnerabilities detected*
{% endif %}

---
{% endfor %}
```

### Accessing Module Data in Loops

In multi-target reports, access scanner data via `t.modules`:

```markdown
{% for t in targets %}
  {{ t.modules.dns_scanner.subdomains|count }} subdomains
  {{ t.modules.ssl_scanner.issuer }}
  {{ t.modules.nuclei_scanner.vulnerabilities|count }} vulnerabilities
{% endfor %}
```

---

## 7. Example Templates

### Executive Summary

```markdown
# Executive Security Summary

**Organization:** {{ tenant.report_company_name }}
**Date:** {{ now|date }}
**Scope:** {{ report.target_count }} target(s)

---

## Risk Overview

| Severity | Count | Status |
|----------|-------|--------|
| Critical | {{ summary.critical_count }} | {% if summary.critical_count > 0 %}IMMEDIATE ACTION{% else %}OK{% endif %} |
| High | {{ summary.high_count }} | {% if summary.high_count > 0 %}URGENT{% else %}OK{% endif %} |
| Medium | {{ summary.medium_count }} | {% if summary.medium_count > 5 %}REVIEW{% else %}OK{% endif %} |
| Low | {{ summary.low_count }} | MONITOR |

## Key Findings

{% if summary.critical_count > 0 %}
### Critical Issues
Critical vulnerabilities were detected that require immediate remediation.
{% endif %}

{% if summary.total_vulnerabilities == 0 %}
No security vulnerabilities were detected during this assessment.
{% endif %}

## Recommendations

1. {% if summary.critical_count > 0 %}Address critical vulnerabilities within 24 hours{% else %}Continue regular monitoring{% endif %}
2. {% if summary.high_count > 0 %}Remediate high-severity issues within 7 days{% else %}Maintain current security posture{% endif %}
3. Review and update security configurations quarterly

---

*Report generated by YADS Security Platform*
```

### SSL Certificate Report

```markdown
# SSL Certificate Status Report

**Generated:** {{ now|datetime }}
**Organization:** {{ tenant.report_company_name }}

---

{% for t in targets %}
## {{ t.domain }}

{% if t.modules.ssl_scanner %}
{% set ssl = t.modules.ssl_scanner %}

| Property | Value |
|----------|-------|
| **Issuer** | {{ ssl.issuer|default('N/A') }} |
| **Subject** | {{ ssl.subject|default('N/A') }} |
| **Valid From** | {{ ssl.not_before|default('N/A') }} |
| **Valid Until** | {{ ssl.not_after|default('N/A') }} |
| **Days Remaining** | {{ ssl.days_until_expiry|default('Unknown') }} |
| **Key Type** | {{ ssl.public_key_type|default('N/A') }} ({{ ssl.public_key_bits|default('?') }} bits) |

{% if ssl.days_until_expiry and ssl.days_until_expiry < 30 %}
**WARNING:** Certificate expires in less than 30 days!
{% endif %}

{% if ssl.is_self_signed %}
**NOTE:** This certificate is self-signed and will not be trusted by browsers.
{% endif %}

### Subject Alternative Names
{% if ssl.subject_alt_names %}
{% for san in ssl.subject_alt_names %}
- {{ san }}
{% endfor %}
{% else %}
No additional SANs configured.
{% endif %}

{% else %}
*No SSL data available for this target*
{% endif %}

---
{% endfor %}
```

### Vulnerability Report

```markdown
# Vulnerability Assessment Report

**Target:** {{ target.domain }}
**Scan Date:** {{ now|datetime }}

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | {{ nuclei.stats.critical|default(0) }} |
| High | {{ nuclei.stats.high|default(0) }} |
| Medium | {{ nuclei.stats.medium|default(0) }} |
| Low | {{ nuclei.stats.low|default(0) }} |
| Info | {{ nuclei.stats.info|default(0) }} |
| **Total** | {{ nuclei.findings|count }} |

---

## Detailed Findings

{% for v in nuclei.findings %}
### {{ loop.index }}. {{ v.name }}

**Severity:** {{ v.severity|upper }}
**Template:** `{{ v.template_id }}`
**Found at:** `{{ v.matched_at }}`

{% if v.description %}
**Description:**
{{ v.description }}
{% endif %}

{% if v.remediation %}
**Remediation:**
{{ v.remediation }}
{% endif %}

{% if v.reference %}
**References:**
{% for ref in v.reference %}
- {{ ref }}
{% endfor %}
{% endif %}

---
{% endfor %}

{% if nuclei.findings|count == 0 %}
No vulnerabilities were detected during this scan.
{% endif %}
```

---

## 8. Data Isolation and Security

### Tenant Isolation

**Important:** All report data is automatically filtered by your tenant. You can only access data belonging to your organization.

This ensures:
- You never accidentally see another tenant's data
- Reports only include targets assigned to your tenant
- All variables automatically respect tenant boundaries

### What This Means

When you use `{{ targets }}` or any other variable, YADS automatically filters to only show:
- Targets where `target.tenant_id` matches your tenant
- Scan results for those targets
- No cross-tenant data exposure is possible

### Platform Admins

Platform administrators (users without a specific tenant assignment) can see data across all tenants. Use this capability responsibly and only for legitimate administrative purposes.

---

## 9. Tips and Best Practices

### Template Design

1. **Start Simple**: Begin with a basic template and add complexity gradually
2. **Use Sections**: Organize reports with clear headings and separators
3. **Handle Missing Data**: Always use `|default()` for optional fields
4. **Test with Real Data**: Preview templates with actual scan data before finalizing

### Performance

1. **Limit Loop Iterations**: Use slicing to limit large lists
   ```markdown
   {% for v in nuclei.findings[:10] %}
   ```
2. **Avoid Deep Nesting**: Keep template logic simple
3. **Use Summaries**: Show counts instead of full lists when appropriate

### Common Patterns

**Show count with conditional:**
```markdown
{% if dns.subdomains|count > 0 %}
Found {{ dns.subdomains|count }} subdomains
{% else %}
No subdomains discovered
{% endif %}
```

**Table with loop:**
```markdown
| Domain | Status |
|--------|--------|
{% for t in targets %}
| {{ t.domain }} | {{ t.status }} |
{% endfor %}
```

**Conditional severity styling:**
```markdown
{% if v.severity == 'critical' %}**CRITICAL**{% elif v.severity == 'high' %}**HIGH**{% else %}{{ v.severity|upper }}{% endif %}
```

### Debugging

- Use the **Preview** feature to test templates with real data
- Check the browser console for template errors
- Start with simple variables and gradually add complexity
- If a variable shows nothing, it may be empty - use `|default()` to verify

---

## Support

For questions about the Report Builder:
- Check the in-app help panel (click "?" in the Report Builder)
- Review example templates in the template library
- Contact support: info@yads-security.com

---

*Documentation for YADS Report Builder v1.17.0*

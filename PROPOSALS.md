# Feature Proposals: Extracting More Value

Here are 4 impactful features we could implement to get more out of your existing domain list:

## 1. Port Scanner (Attack Surface)
**What:** Scan for exposed services on non-standard ports (e.g., 21, 22, 8080, 8443, 3306).
**Why:** Finds forgotten admin panels, databases, or SSH interfaces that shouldn't be public.
**Effort:** Medium (Python `socket` based scanner).

## 2. Wayback Machine Integration (History)
**What:** Query `archive.org` to find historical snapshots of the domain.
**Why:**
*   Recover deleted files or pages.
*   Find old endpoints that might still be active but unlinked.
*   See how the site changed over time.
**Effort:** Low (API query).

## 3. Broken Link Hijacking (Security)
**What:** Extract all external links from the main page and check if the referenced domains are expired.
**Why:** If a domain links to an expired resource (e.g., old campaign site), an attacker can register it and serve malicious content on your trusted site.
**Effort:** Medium (Requires checking DNS for every link).

## 4. Whois & Expiration Monitor (Administrative)
**What:** Fetch the official Whois registration data.
**Why:**
*   **Alert** if a domain is expiring soon (prevent loss).
*   **Verify** registrar details match your policy.
**Effort:** Low (Using `python-whois`).

---
**Recommendation:**
I recommend starting with **Port Scanner** (#1) for security insight or **Wayback Machine** (#2) for interesting OSINT data.
**Which one should we implement?**

## 5. Data Insights & Visualization (Leveraging Existing Data)
**What:** Build new views/dashboards using the data we already collect.
*   **Tech Radar:** Pie charts/Graphs showing "Top Web Servers", "Most Common Technologies" (e.g. Nginx vs Apache), and "ASN Distribution".
*   **Vulnerability Dashboard:** Aggregate view of *all* CVEs across *all* targets, grouped by severity.
*   **Critical Risk Feed:** A dedicated page listing only "Urgent" issues: Subdomain Takeovers, Critical CVEs, and Expiring Certificates (< 7 days).
*   **Global Search:** "Find all targets using jQuery" (Search deep into the JSON results).
**Why:** Helps you make sense of the data at scale without running new scans.
**Effort:** Medium (Frontend + Aggregation Queries).
# New Feature Proposals for YADS

Based on the current stable foundation (Scan Engine, Multi-Tenancy, Graph, Nuclei), here are advanced feature proposals to take YADS to the 'Commercial/Enterprise' level.

## 1. AI-Powered Executive Reporting 🧠
**Concept**: Technical data (CVEs, Json) is hard for managers to digest.
**Feature**:
*   Integrate a Local LLM (Ollama) or OpenAI API.
*   **"Generate Management Report"**: One-click PDF that summarizes: "Security Posture improved by 10%. 3 Critical risks found in 'Marketing Subdomains'. Recommended action: Patch Nginx."
*   **"Explain this Vulnerability"**: Button next to a CVE to get a human-readable explanation and remediation steps.

## 2. Visual Regression (Defacement Monitor) 👁️
**Concept**: Sometimes a site is hacked but no technical vulnerability is detected (content defacement).
**Feature**:
*   Store "Baseline" screenshots.
*   On each scan, compare the new screenshot with the baseline using pixel diffing.
*   **Alert**: "Visual deviation > 15% detected on example.com".
*   Excellent for detecting "Broken UI" deployments too.

## 3. Cloud Asset Enumeration ☁️
**Concept**: Modern infrastructure is often hidden in public cloud buckets, not just DNS.
**Feature**:
*   **Bucket Brute-force**: Generate permutations of the domain (`company-backup`, `company-dev`, `company-assets`) and check AWS S3, Google Cloud Storage, and Azure Blobs.
*   **Exposure Check**: Auto-list files in open buckets.

## 4. Credential & Leak Monitoring 🕵️
**Concept**: Emails found on the website (OSINT) might be compromised.
**Feature**:
*   **HIBP Integration**: Auto-check discovered emails against "Have I Been Pwned".
*   **Git Leaks**: Scan public GitHub repositories for the domain name + "password", "api_key", "secret".

## 5. Attack Path Visualization 🕸️
**Concept**: The Network Graph shows connections. Attack Path shows *risk flow*.
**Feature**:
*   Highlight "chains" of compromise.
*   Example: `Subdomain A (Low Security)` -> `Shared IP` -> `Main DB (High Security)`.
*   "If I hack A, am I on the same server as B?"

## 6. JIRA / Ticket Integration 🎫
**Concept**: Finding bugs is useless if they aren't fixed.
**Feature**:
*   **"Create Ticket"**: Button on a finding.
*   **Bi-directional Sync**: When the JIRA ticket is "Closed", YADS auto-rescans the target to verify the fix.

---

### Recommendation
I recommend starting with **Visual Regression (#2)** (High visual impact, extremely useful for ops/security) or **Cloud Enumeration (#3)** (High discovery value).

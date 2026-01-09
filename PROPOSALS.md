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

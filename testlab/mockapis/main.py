"""
Mock External API Server for YADS Testlab.

Configure YADS to use these endpoints instead of real external APIs by setting
environment variables in data/config.env:
  ABUSEIPDB_BASE_URL=http://testlab-mockapis:9000
  HIBP_BASE_URL=http://testlab-mockapis:9000
  OTX_BASE_URL=http://testlab-mockapis:9000
  VIRUSTOTAL_BASE_URL=http://testlab-mockapis:9000
  SHODAN_BASE_URL=http://testlab-mockapis:9000
  CENSYS_BASE_URL=http://testlab-mockapis:9000
  PHISHTANK_BASE_URL=http://testlab-mockapis:9000
"""
from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse

app = FastAPI(title="YADS Testlab Mock APIs")

TESTLAB_SUBNET = "172.30."

def _is_testlab(ip: str) -> bool:
    return ip.startswith(TESTLAB_SUBNET)


# ── Health ────────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "service": "yads-testlab-mock-apis"}


# ── AbuseIPDB ─────────────────────────────────────────────────────────────────
@app.get("/api/v2/check")
def abuseipdb_check(ipAddress: str = Query(...)):
    if _is_testlab(ipAddress):
        return {"data": {
            "ipAddress": ipAddress,
            "isPublic": True,
            "abuseConfidenceScore": 87,
            "countryCode": "RU",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "TestLab Bad Actor ISP",
            "totalReports": 142,
            "lastReportedAt": "2024-01-15T10:00:00+00:00",
        }}
    return {"data": {"ipAddress": ipAddress, "abuseConfidenceScore": 0, "totalReports": 0}}


# ── HIBP ──────────────────────────────────────────────────────────────────────
@app.get("/api/v3/breachesforaccountwithpaste")
@app.get("/api/v3/breach/search/domain/{domain}")
def hibp_domain(domain: str = "testlab.local"):
    if "testlab" in domain:
        return [
            {"Name": "TestBreachA", "Title": "TestLab DB Dump 2024", "PwnCount": 15000,
             "BreachDate": "2024-01-01", "DataClasses": ["Email addresses", "Passwords", "Usernames"]},
            {"Name": "TestBreachB", "Title": "TestLab Email Leak", "PwnCount": 3200,
             "BreachDate": "2023-06-15", "DataClasses": ["Email addresses"]},
        ]
    return []

@app.get("/api/v3/breachesforaccountwithpaste/{email}")
def hibp_email(email: str):
    if "testlab" in email:
        return [{"Name": "TestBreachA", "PwnCount": 15000}]
    return []


# ── AlienVault OTX ────────────────────────────────────────────────────────────
@app.get("/api/v1/indicators/IPv4/{ip}/general")
def otx_ip(ip: str):
    if _is_testlab(ip):
        return {
            "pulse_info": {"count": 5, "pulses": [
                {"name": "Malicious C2 Infrastructure", "tags": ["malware", "c2"]},
                {"name": "Phishing Campaign 2024", "tags": ["phishing"]},
            ]},
            "reputation": 3,
            "type": "IPv4",
        }
    return {"pulse_info": {"count": 0, "pulses": []}, "reputation": 0}


# ── VirusTotal ────────────────────────────────────────────────────────────────
@app.get("/api/v3/ip_addresses/{ip}")
def vt_ip(ip: str):
    if _is_testlab(ip):
        return {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 8, "suspicious": 3, "undetected": 42, "harmless": 10},
            "reputation": -12,
            "country": "RU",
        }}}
    return {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}, "reputation": 0}}}


# ── Shodan ────────────────────────────────────────────────────────────────────
@app.get("/shodan/host/{ip}")
def shodan_host(ip: str):
    if _is_testlab(ip):
        return {
            "ip_str": ip,
            "org": "TestLab Hosting",
            "country_name": "Germany",
            "asn": "AS65001",
            "ports": [21, 22, 23, 80, 443, 3306, 8080],
            "vulns": ["CVE-2021-44228", "CVE-2021-34527"],
            "data": [
                {"port": 22, "transport": "tcp", "product": "OpenSSH", "version": "7.4", "banner": "SSH-2.0-OpenSSH_7.4"},
                {"port": 80, "transport": "tcp", "product": "Apache httpd", "version": "2.4.6"},
                {"port": 3306, "transport": "tcp", "product": "MySQL", "version": "5.7.30"},
            ],
        }
    return {"ip_str": ip, "ports": [], "data": []}


# ── ASN / IP Range Mocking (ipinfo, RIPE, BGPView) ────────────────────────────

@app.get("/ipinfo/{ip}/json")
def mock_ipinfo(ip: str):
    if _is_testlab(ip):
        return {
            "ip": ip,
            "hostname": "target.testlab.local",
            "city": "Berlin",
            "region": "Berlin",
            "country": "DE",
            "loc": "52.5200,13.4050",
            "org": "AS65001 TestLab Autonomous System",
            "postal": "10115",
            "timezone": "Europe/Berlin",
        }
    return {"ip": ip, "bogon": True}

@app.get("/data/network-info/data.json")
def mock_ripe_net(resource: str):
    if _is_testlab(resource):
        return {"data": {"asns": ["65001"], "prefix": "172.30.0.0/24"}}
    return {"data": {"asns": []}}

@app.get("/data/as-overview/data.json")
def mock_ripe_asn(resource: str):
    if resource == "65001" or resource == "AS65001":
        return {"data": {
            "holder": "TestLab Internal Network",
            "block": {
                "name": "TESTLAB-ASN",
                "country": "DE",
                "description": "YADS Test Environment ASN",
            }
        }}
    return {"data": {}}

@app.get("/data/announced-prefixes/data.json")
def mock_ripe_prefixes(resource: str):
    if resource == "65001" or resource == "AS65001":
        return {"data": {"prefixes": [
            {"prefix": "172.30.0.0/24"},
            {"prefix": "10.0.0.0/8"},
        ]}}
    return {"data": {"prefixes": []}}

@app.get("/api/v1/asn/{asn}/prefixes")
def mock_bgpview_prefixes(asn: str):
    if asn == "65001":
        return {"data": {"ipv4_prefixes": [
            {"prefix": "172.30.0.0/24", "name": "testlab-subnet", "description": "Core Testlab Network", "country_code": "DE"},
            {"prefix": "10.0.0.0/8", "name": "internal-mock-range", "description": "Internal Mocked Range", "country_code": "DE"},
        ]}}
    return {"data": {"ipv4_prefixes": []}}


# ── PhishTank ─────────────────────────────────────────────────────────────────
@app.post("/checkurl/")
async def phishtank_check(request_type: str = "json", url: str = ""):
    if "testlab" in url:
        return {"results": {"in_database": True, "phish_id": "99999", "verified": True,
                            "verified_at": "2024-01-15T10:00:00+00:00", "valid": True}}
    return {"results": {"in_database": False, "valid": True}}

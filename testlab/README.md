# YADS Test Lab

Isolated vulnerable target stack for validating all YADS scanner modules.

## Quick Start (via Release Manager)

1. Open **YADS Release Manager** → **Test Lab** page
2. Click **Init** (first time or after a broken state) — pulls images, builds custom services
3. Click **Start** — starts all containers
4. In YADS, add targets under Tenant **Frischkorn** (test-only):
   - `dvwa.testlab.local`
   - `juice.testlab.local`
   - `badssl.testlab.local`
   - `badheaders.testlab.local`
   - `graphql.testlab.local`
   - `ws.testlab.local`
   - `gitexpose.testlab.local`
   - `loginpage.testlab.local`
   - `dsgvo.testlab.local`

## Manual Operation

```bash
# Initialize (first time / reset)
docker compose -f docker-compose.testlab.yml down --remove-orphans -v
docker compose -f docker-compose.testlab.yml pull
docker compose -f docker-compose.testlab.yml build
docker compose -f docker-compose.testlab.yml create

# Start
docker compose -f docker-compose.testlab.yml up -d

# Stop
docker compose -f docker-compose.testlab.yml down

# Status
docker compose -f docker-compose.testlab.yml ps
```

## DNS Resolution

For the YADS worker to resolve `*.testlab.local`, the CoreDNS server must be
reachable. The worker needs to be in the `yads-testlab` network:

```bash
docker network connect yads-testlab yads-worker
```

Or add to docker-compose.yml under the worker service:
```yaml
networks:
  - default
  - yads-testlab

networks:
  yads-testlab:
    external: true
```

Then set in YADS target: use `172.30.0.20` directly or configure `/etc/resolv.conf`
in the worker container to use `172.30.0.10` (CoreDNS).

## Mock APIs for Passive Scanners

To use mock APIs instead of real external services, add to `data/config.env`:

```
ABUSEIPDB_BASE_URL=http://testlab-mockapis:9000
HIBP_BASE_URL=http://testlab-mockapis:9000
OTX_BASE_URL=http://testlab-mockapis:9000
VIRUSTOTAL_BASE_URL=http://testlab-mockapis:9000
SHODAN_BASE_URL=http://testlab-mockapis:9000
```

The mock APIs return deterministic "bad" results for any IP in `172.30.x.x`.

## Scanner Coverage

| Module | Target | Expected Finding |
|---|---|---|
| `dns_scanner` | dns.testlab.local | 10+ DNS records |
| `axfr_scanner` | dns.testlab.local | Zone transfer **succeeds** |
| `subdomain_takeover_scanner` | dns.testlab.local | `staging` CNAME → dangling S3 |
| `ssl_scanner` / `tls_deep_scanner` | badssl.testlab.local | TLS 1.0, RC4, self-signed, cert mismatch |
| `cert_mismatch_scanner` | badssl.testlab.local | CN=wrong.domain.example |
| `http_headers_scanner` | badheaders.testlab.local | All security headers missing |
| `cookie_scanner` | badheaders.testlab.local | Cookies without Secure/HttpOnly/SameSite |
| `cors_scanner` | badheaders.testlab.local | `Access-Control-Allow-Origin: *` |
| `waf_detector` | badheaders.testlab.local | No WAF detected |
| `email_security_scanner` | testlab.local | No SPF/DKIM/DMARC |
| `security_txt_scanner` | loginpage.testlab.local | 404 — missing |
| `js_secrets_scanner` | gitexpose.testlab.local | AWS/Stripe/Google keys in JS |
| `git_exposure_scanner` | gitexpose.testlab.local | /.git/HEAD, /.env, /backup.sql exposed |
| `graphql_scanner` | graphql.testlab.local | Introspection on, sensitive fields |
| `websocket_scanner` | ws.testlab.local | ws:// (no TLS), no auth |
| `login_scanner` | loginpage.testlab.local | /admin, /wp-login.php, /api/auth/login |
| `password_spray_mapper` | loginpage.testlab.local | No rate limiting, no lockout |
| `nuclei_scanner` | dvwa.testlab.local | SQL injection, XSS (DVWA templates) |
| `web_analyzer` | juice.testlab.local | Express.js, Angular detected |
| `api_security_scanner` | juice.testlab.local | /api/users unauthenticated |
| `threat_intel_scanner` | 172.30.0.20 | Mock: AbuseIPDB score 87, OTX 5 pulses |
| `leaked_credentials` | testlab.local | Mock HIBP: 2 breaches |
| `phishing_scanner` | testlab.local | Mock PhishTank: listed |
| `dsgvo_scanner` | dsgvo.testlab.local | No Privacy Policy, tracking cookies found |
| `asn_scanner` | 172.30.0.20 | AS65001 TestLab, 2 prefixes, detail via BGPView |

## Network Architecture

```
┌─────────────────────────────────────────────────────┐
│  Docker Network: yads-testlab (172.30.0.0/24)        │
│                                                       │
│  172.30.0.10  CoreDNS (AXFR enabled)                 │
│  172.30.0.19  MySQL (DVWA backend)                   │
│  172.30.0.20  DVWA                                    │
│  172.30.0.21  OWASP Juice Shop                        │
│  172.30.0.22  BadSSL (weak TLS, cert mismatch)        │
│  172.30.0.23  Bad Headers (Nginx)                     │
│  172.30.0.24  GraphQL (introspection on)              │
│  172.30.0.25  WebSocket (ws://, no auth)              │
│  172.30.0.26  Git/File Exposure (Nginx)               │
│  172.30.0.27  Login Surface (FastAPI)                 │
│  172.30.0.30  Mock External APIs (FastAPI)            │
│  172.30.0.40  DSGVO / GDPR Test (Nginx)               │
└─────────────────────────────────────────────────────┘
```

**IMPORTANT:** Never expose testlab container ports to the host or internet.
All containers are only reachable within the Docker network.

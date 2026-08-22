"""
YADS Module Registry
====================
Central definition of all scanner modules.

Adding a new scanner module requires only one entry here. Everything else
(worker dispatch, security findings aggregation, scan UI dropdowns,
attack surface heatmap, change feed labels) reads from this registry.

Fields per entry:
  name            str   module_name (must match BaseScannerModule.module_name)
  label           str   English display label
  label_de        str   German display label
  category        str   UI group: recon|web|config|exposure|threat|active
  module_path     str   "package.module:ClassName" for lazy import
  worker_note     str   Progress message shown during scanning
  requires_http   bool  Skip if no HTTP connectivity (port 80/443 closed)
  requires_https  bool  Skip if no HTTPS connectivity (port 443 closed)
  default_on      bool  Pre-checked in the scan type dropdown
  finding_module  bool  Include in Security Findings / Attack Surface aggregation
  extractor       str   Findings extraction strategy (see security_findings.py):
                        "generic"   — reads data["findings"] directly (standard for new modules)
                        "<name>"    — uses module-specific extractor in security_findings.py
  custom_dispatch bool  Worker has special dispatch logic; registry loop skips this module.
                        The module is still registered for UI/label/finding purposes.
  passive         bool  True = passive/safe (read-only, no probing, no port scanning).
                        False = active/intrusive (fuzzing, port scans, exploit probes, etc.).
  degraded_without_binary str  Optional binary name. Module works but in limited/fallback mode
                        when the binary is absent. UI shows "limited mode" badge instead of
                        disabling the checkbox.
"""

from collections import OrderedDict
from importlib import import_module
from typing import Any, Dict, List, Optional


class ModuleDef:
    __slots__ = (
        "name", "label", "label_de", "category", "module_path",
        "worker_note", "requires_http", "requires_https", "default_on",
        "finding_module", "extractor", "custom_dispatch", "report_view", "passive",
        "requires_binary", "degraded_without_binary",
    )

    def __init__(
        self,
        name: str,
        label: str,
        label_de: str,
        category: str,
        module_path: str = "",
        worker_note: str = "",
        requires_http: bool = False,
        requires_https: bool = False,
        default_on: bool = False,
        finding_module: bool = False,
        extractor: str = "generic",
        custom_dispatch: bool = False,
        report_view: Optional[str] = None,
        passive: bool = True,
        requires_binary: Optional[str] = None,
        degraded_without_binary: Optional[str] = None,
    ):
        self.name = name
        self.label = label
        self.label_de = label_de
        self.category = category
        self.module_path = module_path
        self.worker_note = worker_note
        self.requires_http = requires_http
        self.requires_https = requires_https
        self.default_on = default_on
        self.finding_module = finding_module
        self.extractor = extractor
        self.custom_dispatch = custom_dispatch
        # Explicit report page URL. None → auto-resolves to /reports/module/{name}
        self.report_view = report_view
        self.passive = passive
        # Hard dependency: module cannot run without this binary; UI disables the checkbox.
        self.requires_binary = requires_binary
        # Soft dependency: module works but degrades to fallback mode without this binary.
        self.degraded_without_binary = degraded_without_binary

    def get_report_url(self) -> str:
        """Return the report URL — explicit override or auto-generated generic."""
        return self.report_view or f"/reports/module/{self.name}"

    def load_class(self):
        """Lazy-load and return the module class."""
        if not self.module_path:
            raise ValueError(f"No module_path defined for {self.name}")
        pkg, cls_name = self.module_path.rsplit(":", 1)
        mod = import_module(pkg)  # nosec B417 — pkg is hardcoded in module_registry, never user-supplied
        return getattr(mod, cls_name)

    def __repr__(self) -> str:
        return f"<ModuleDef {self.name}>"


# ---------------------------------------------------------------------------
# Category display metadata (order matters — defines dropdown order)
# ---------------------------------------------------------------------------
CATEGORIES: List[Dict[str, str]] = [
    {"id": "recon",    "label": "Reconnaissance",      "label_de": "Aufklärung",          "color": "indigo"},
    {"id": "web",      "label": "Web Analysis",         "label_de": "Web-Analyse",          "color": "sky"},
    {"id": "config",   "label": "Configuration",        "label_de": "Konfiguration",        "color": "emerald"},
    {"id": "exposure", "label": "Exposure & Secrets",   "label_de": "Exposition & Secrets", "color": "amber"},
    {"id": "threat",   "label": "Threat Intel",         "label_de": "Bedrohungsanalyse",    "color": "rose"},
    {"id": "active",   "label": "Active Scanning",      "label_de": "Aktives Scannen",      "color": "orange"},
    {"id": "report",   "label": "Reports & Exports",    "label_de": "Berichte & Exporte",   "color": "violet"},
]

# ---------------------------------------------------------------------------
# Module Registry (insertion order = scan execution order)
# ---------------------------------------------------------------------------
REGISTRY: OrderedDict[str, ModuleDef] = OrderedDict([

    # ── Reconnaissance ────────────────────────────────────────────────────
    ("subdomain_scanner", ModuleDef(
        name="subdomain_scanner",
        label="Subdomain Recon",
        label_de="Subdomain-Aufklärung",
        category="recon",
        module_path="yads.modules.dns_scanner:DnsScanner",
        worker_note="Enumerating subdomains via Certificate Transparency...",
        default_on=False,
        finding_module=False,
        custom_dispatch=True,  # uses auto-queue logic in worker
    )),
    ("dns_scanner", ModuleDef(
        name="dns_scanner",
        label="DNS Records",
        label_de="DNS-Einträge",
        category="recon",
        module_path="yads.modules.dns_scanner:DnsScanner",
        worker_note="Fetching DNS records...",
        finding_module=False,
        custom_dispatch=True,
    )),
    ("axfr_scanner", ModuleDef(
        name="axfr_scanner",
        label="DNS Zone Transfer",
        label_de="DNS-Zonentransfer",
        category="recon",
        module_path="yads.modules.axfr_scanner:AXFRScanner",
        worker_note="Testing DNS zone transfer (AXFR)...",
        finding_module=True,
        extractor="axfr_scanner",
        passive=False,
    )),
    ("tld_scanner", ModuleDef(
        name="tld_scanner",
        label="TLD Scanner",
        label_de="TLD-Scanner",
        category="recon",
        module_path="yads.modules.tld_scanner:TLDScanner",
        worker_note="Scanning registered TLD variations...",
        finding_module=False,
    )),
    ("typosquat_scanner", ModuleDef(
        name="typosquat_scanner",
        label="Typosquatting",
        label_de="Typosquatting",
        category="recon",
        module_path="yads.modules.typosquat_scanner:TyposquatScanner",
        worker_note="Checking typosquatting domains...",
        default_on=True,
        finding_module=False,
    )),
    ("rpki_scanner", ModuleDef(
        name="rpki_scanner",
        label="RPKI / BGP",
        label_de="RPKI / BGP",
        category="recon",
        module_path="yads.modules.rpki_scanner:RpkiScanner",
        worker_note="Validating RPKI route origin authorizations...",
        finding_module=True,
        extractor="generic",
    )),
    ("dormant_detector", ModuleDef(
        name="dormant_detector",
        label="Dormant Domain Detector",
        label_de="Erkennung inaktiver Domains",
        category="recon",
        module_path="yads.modules.dormant_detector:DormantDetectorScanner",
        worker_note="Analyzing activity signals for dormancy...",
        requires_http=False,
        requires_https=False,
        default_on=True,
        finding_module=False,
        passive=True,
        report_view="/dormant-domains",
    )),

    # ── Web Analysis ───────────────────────────────────────────────────────
    ("web_analyzer", ModuleDef(
        name="web_analyzer",
        label="Web Analyzer",
        label_de="Web-Analyzer",
        category="web",
        module_path="yads.modules.web_analyzer:WebAnalyzer",
        worker_note="Analyzing web application...",
        requires_http=True,
        default_on=True,
        # Redirect-chain health issues (#28) are the only thing this module
        # surfaces to Unified Findings — see the narrowly-scoped web_analyzer
        # branch in security_findings.py's _extract_findings().
        finding_module=True,
        custom_dispatch=True,
    )),
    ("ssl_scanner", ModuleDef(
        name="ssl_scanner",
        label="SSL Scanner",
        label_de="SSL-Scanner",
        category="web",
        module_path="yads.modules.ssl_scanner:SSLScanner",
        worker_note="Analyzing SSL/TLS certificate...",
        requires_https=True,
        default_on=True,
        finding_module=False,
        custom_dispatch=True,  # post-processes extracted domains
        report_view="/cert-timeline",
    )),
    ("http_headers", ModuleDef(
        name="http_headers",
        label="HTTP Headers",
        label_de="HTTP-Header",
        category="web",
        module_path="yads.modules.http_headers_scanner:HTTPHeadersScanner",
        worker_note="Checking HTTP security headers...",
        requires_http=True,
        finding_module=True,
        extractor="http_headers",
    )),
    ("cookie_scanner", ModuleDef(
        name="cookie_scanner",
        label="Cookie Security",
        label_de="Cookie-Sicherheit",
        category="web",
        module_path="yads.modules.cookie_scanner:CookieScanner",
        worker_note="Analyzing cookie security...",
        requires_http=True,
        finding_module=True,
        extractor="cookie_scanner",
    )),
    ("cors_scanner", ModuleDef(
        name="cors_scanner",
        label="CORS",
        label_de="CORS",
        category="web",
        module_path="yads.modules.cors_scanner:CORSScanner",
        worker_note="Testing CORS policy...",
        requires_http=True,
        finding_module=True,
        extractor="cors_scanner",
        passive=False,
    )),
    ("csp_scanner", ModuleDef(
        name="csp_scanner",
        label="CSP Scanner",
        label_de="CSP-Scanner",
        category="web",
        module_path="yads.modules.csp_scanner:CSPScanner",
        worker_note="Analyzing Content-Security-Policy...",
        requires_http=True,
        finding_module=False,
    )),
    ("security_txt", ModuleDef(
        name="security_txt",
        label="Security.txt",
        label_de="Security.txt",
        category="web",
        module_path="yads.modules.security_txt_scanner:SecurityTxtScanner",
        worker_note="Checking security.txt (RFC 9116)...",
        finding_module=True,
        extractor="security_txt",
    )),
    ("catchall_detector", ModuleDef(
        name="catchall_detector",
        label="Catch-All Page Detector",
        label_de="Catch-All-Seiten-Erkennung",
        category="web",
        module_path="yads.modules.catchall_detector:CatchallDetectorScanner",
        worker_note="Checking for parked/catch-all landing page...",
        requires_http=True,
        default_on=False,      # explicit opt-in — extra requests + optional LLM cost
        finding_module=False,  # recon/triage signal, not a vulnerability
        passive=True,
    )),
    ("cert_mismatch", ModuleDef(
        name="cert_mismatch",
        label="Cert Mismatch",
        label_de="Zertifikat-Abweichung",
        category="web",
        module_path="yads.modules.cert_mismatch_scanner:CertMismatchScanner",
        worker_note="Checking certificate/domain match...",
        finding_module=True,
        extractor="cert_mismatch",
    )),

    # ── Configuration ──────────────────────────────────────────────────────
    ("email_security", ModuleDef(
        name="email_security",
        label="Email Security",
        label_de="E-Mail-Sicherheit",
        category="config",
        module_path="yads.modules.email_security_scanner:EmailSecurityScanner",
        worker_note="Checking SPF/DKIM/DMARC...",
        finding_module=True,
        extractor="email_security",
        report_view="/email-security",
    )),
    ("dsgvo_scanner", ModuleDef(
        name="dsgvo_scanner",
        label="Privacy / GDPR",
        label_de="Datenschutz / DSGVO",
        category="config",
        module_path="yads.modules.dsgvo_scanner:DsgvoScanner",
        worker_note="Scanning GDPR/DSGVO compliance indicators...",
        requires_http=True,
        finding_module=True,
        extractor="generic",
    )),
    ("git_exposure", ModuleDef(
        name="git_exposure",
        label="Git Exposure",
        label_de="Git-Exposition",
        category="config",
        module_path="yads.modules.git_exposure_scanner:GitExposureScanner",
        worker_note="Scanning for exposed .git and sensitive files...",
        requires_http=True,
        finding_module=True,
        extractor="generic",
        passive=False,
    )),
    ("seed_files_scanner", ModuleDef(
        name="seed_files_scanner",
        label="Seed Files",
        label_de="Seed-Dateien",
        category="config",
        module_path="yads.modules.seed_files_scanner:SeedFilesScanner",
        worker_note="Analyzing robots.txt & sitemap.xml...",
        requires_http=True,
        finding_module=False,
    )),
    ("metadata_scanner", ModuleDef(
        name="metadata_scanner",
        label="Document Metadata",
        label_de="Dokument-Metadaten",
        category="config",
        module_path="yads.modules.metadata_scanner:MetadataScanner",
        worker_note="Extracting document metadata...",
        requires_http=True,
        finding_module=True,
        extractor="generic",
    )),

    # ── Exposure & Secrets ─────────────────────────────────────────────────
    ("shodan_censys", ModuleDef(
        name="shodan_censys",
        label="Shodan / Censys",
        label_de="Shodan / Censys",
        category="exposure",
        module_path="yads.modules.shodan_censys_scanner:ShodanCensysScanner",
        worker_note="Querying Shodan/Censys...",
        finding_module=True,
        extractor="shodan_censys",
    )),
    ("js_secrets", ModuleDef(
        name="js_secrets",
        label="JS Secrets",
        label_de="JS-Secrets",
        category="exposure",
        module_path="yads.modules.js_secrets_scanner:JsSecretsScanner",
        worker_note="Scanning JavaScript files for secrets...",
        requires_http=True,
        finding_module=True,
        extractor="generic",
        report_view="/secrets",
    )),
    ("wayback_scanner", ModuleDef(
        name="wayback_scanner",
        label="Wayback Machine",
        label_de="Wayback Machine",
        category="exposure",
        module_path="yads.modules.wayback_scanner:WaybackScanner",
        worker_note="Checking Wayback Machine for historical exposures...",
        finding_module=True,
        extractor="generic",
    )),
    ("external_resources", ModuleDef(
        name="external_resources",
        label="External Resources",
        label_de="Externe Ressourcen",
        category="exposure",
        module_path="yads.modules.external_resources_scanner:ExternalResourcesScanner",
        worker_note="Analyzing external resource loading...",
        requires_http=True,
        finding_module=True,
        extractor="generic",
    )),
    ("cloud_scanner", ModuleDef(
        name="cloud_scanner",
        label="Cloud Assets",
        label_de="Cloud-Assets",
        category="exposure",
        module_path="yads.modules.cloud_scanner:CloudScanner",
        worker_note="Scanning for cloud asset exposure...",
        finding_module=False,
        report_view="/cloud-assets",
    )),

    # ── Threat Intel ────────────────────────────────────────────────────────
    ("threat_intel", ModuleDef(
        name="threat_intel",
        label="Threat Intel",
        label_de="Bedrohungsintelligenz",
        category="threat",
        module_path="yads.modules.threat_intel_scanner:ThreatIntelScanner",
        worker_note="Querying threat intelligence feeds...",
        finding_module=True,
        extractor="threat_intel",
    )),
    ("subdomain_takeover", ModuleDef(
        name="subdomain_takeover",
        label="Subdomain Takeover",
        label_de="Subdomain-Takeover",
        category="threat",
        module_path="yads.modules.subdomain_takeover_scanner:SubdomainTakeoverScanner",
        worker_note="Checking for subdomain takeover risks...",
        finding_module=True,
        extractor="generic",
        passive=False,
    )),
    ("nuclei_scanner", ModuleDef(
        name="nuclei_scanner",
        label="Nuclei",
        label_de="Nuclei",
        category="threat",
        module_path="yads.modules.nuclei_scanner:NucleiScanner",
        worker_note="Running Nuclei vulnerability scanner...",
        requires_http=True,
        finding_module=False,
        custom_dispatch=True,
        passive=False,
    )),
    ("banner_grabber", ModuleDef(
        name="banner_grabber",
        label="Service Fingerprinting",
        label_de="Service-Fingerprinting",
        category="threat",
        module_path="yads.modules.banner_grabber:BannerGrabber",
        worker_note="Grabbing service banners and fingerprinting...",
        finding_module=True,
        extractor="generic",
        passive=False,
    )),

    # ── Active Scanning ────────────────────────────────────────────────────
    ("port_scanner", ModuleDef(
        name="port_scanner",
        label="Port Scanner",
        label_de="Port-Scanner",
        category="active",
        module_path="yads.modules.port_scanner:PortScanner",
        worker_note="Running port scan...",
        finding_module=False,
        custom_dispatch=True,
        report_view="/ports",
        passive=False,
    )),
    ("nmap_scanner", ModuleDef(
        name="nmap_scanner",
        label="Nmap",
        label_de="Nmap",
        category="active",
        module_path="yads.modules.nmap_scanner:NmapScanner",
        worker_note="Running stealth Nmap scan...",
        finding_module=False,
        report_view="/ports",
        passive=False,
        degraded_without_binary="nmap",
    )),
    ("crawler", ModuleDef(
        name="crawler",
        label="Site Crawler",
        label_de="Site-Crawler",
        category="active",
        module_path="yads.modules.crawler:Crawler",
        worker_note="Crawling website...",
        requires_http=True,
        finding_module=False,
        custom_dispatch=True,
        passive=False,
    )),
    ("content_discovery", ModuleDef(
        name="content_discovery",
        label="Content Discovery",
        label_de="Content-Discovery",
        category="active",
        module_path="yads.modules.content_discovery:ContentDiscoveryScanner",
        worker_note="Running content discovery...",
        requires_http=True,
        finding_module=False,
        custom_dispatch=True,
        passive=False,
    )),
    ("visual_osint", ModuleDef(
        name="visual_osint",
        label="Visual OSINT",
        label_de="Visuelles OSINT",
        category="active",
        module_path="yads.modules.visual_osint:VisualOSINT",
        worker_note="Running Visual OSINT...",
        requires_http=True,
        finding_module=False,
        custom_dispatch=True,
    )),
    ("deception_detector", ModuleDef(
        name="deception_detector",
        label="Deception Detector",
        label_de="Täuschungs-Detektor",
        category="active",
        module_path="yads.modules.deception_detector:DeceptionDetector",
        worker_note="Running Deception Detector...",
        finding_module=False,
        custom_dispatch=True,
        passive=False,
    )),
    ("infrastructure_scanner", ModuleDef(
        name="infrastructure_scanner",
        label="Infrastructure",
        label_de="Infrastruktur",
        category="active",
        module_path="yads.modules.infrastructure_scanner:InfrastructureScanner",
        worker_note="Scanning infrastructure...",
        finding_module=False,
        custom_dispatch=True,
        report_view="/ports",
        passive=False,
    )),

    ("waf_detector", ModuleDef(
        name="waf_detector",
        label="WAF / CDN Detection",
        label_de="WAF / CDN-Erkennung",
        category="web",
        module_path="yads.modules.waf_detector:WafDetector",
        worker_note="Detecting WAF/CDN and bypass risks...",
        requires_http=True,
        finding_module=True,
        extractor="generic",
        passive=False,
    )),
    ("asn_scanner", ModuleDef(
        name="asn_scanner",
        label="ASN / IP Ranges",
        label_de="ASN / IP-Bereiche",
        category="recon",
        module_path="yads.modules.asn_scanner:AsnScanner",
        worker_note="Discovering ASN and IP ranges...",
        finding_module=True,
        extractor="generic",
    )),
    ("login_scanner", ModuleDef(
        name="login_scanner",
        label="Login & Auth Surface",
        label_de="Login & Auth-Oberfläche",
        category="web",
        module_path="yads.modules.login_scanner:LoginScanner",
        worker_note="Mapping login and authentication surfaces...",
        requires_http=True,
        finding_module=True,
        extractor="generic",
    )),
    ("ipv6_scanner", ModuleDef(
        name="ipv6_scanner",
        label="IPv6 Attack Surface",
        label_de="IPv6-Angriffsfläche",
        category="recon",
        module_path="yads.modules.ipv6_scanner:IPv6Scanner",
        worker_note="Scanning IPv6 attack surface...",
        finding_module=True,
        extractor="generic",
    )),
    ("open_redirect_scanner", ModuleDef(
        name="open_redirect_scanner",
        label="Open Redirect",
        label_de="Open Redirect",
        category="web",
        module_path="yads.modules.open_redirect_scanner:OpenRedirectScanner",
        worker_note="Testing for open redirect vulnerabilities...",
        requires_http=True,
        finding_module=True,
        extractor="generic",
        passive=False,
    )),
    ("dns_history_scanner", ModuleDef(
        name="dns_history_scanner",
        label="DNS History",
        label_de="DNS-Historie",
        category="recon",
        module_path="yads.modules.dns_history_scanner:DnsHistoryScanner",
        worker_note="Querying passive DNS and certificate logs...",
        finding_module=True,
        extractor="generic",
    )),
    ("phishing_scanner", ModuleDef(
        name="phishing_scanner",
        label="Phishing Detection",
        label_de="Phishing-Erkennung",
        category="threat",
        module_path="yads.modules.phishing_scanner:PhishingScanner",
        worker_note="Checking phishing databases and brand abuse...",
        finding_module=True,
        extractor="generic",
    )),
    ("tls_deep_scanner", ModuleDef(
        name="tls_deep_scanner",
        label="TLS Deep Scan",
        label_de="TLS-Tiefenanalyse",
        category="web",
        module_path="yads.modules.tls_deep_scanner:TlsDeepScanner",
        worker_note="Performing comprehensive TLS configuration analysis...",
        requires_https=True,
        finding_module=True,
        extractor="generic",
        report_view="/cert-timeline",
    )),
    ("ct_monitor", ModuleDef(
        name="ct_monitor",
        label="CT Log Monitor",
        label_de="CT-Log-Überwachung",
        category="recon",
        module_path="yads.modules.ct_monitor:CtMonitor",
        worker_note="Monitoring Certificate Transparency logs...",
        finding_module=True,
        extractor="generic",
    )),
    ("email_harvester", ModuleDef(
        name="email_harvester",
        label="Email Harvesting",
        label_de="E-Mail-Erkennung",
        category="threat",
        module_path="yads.modules.email_harvester:EmailHarvester",
        worker_note="Discovering exposed email addresses and employee OSINT...",
        finding_module=True,
        extractor="generic",
    )),
    ("dependency_confusion", ModuleDef(
        name="dependency_confusion",
        label="Dependency Confusion",
        label_de="Dependency Confusion",
        category="active",
        module_path="yads.modules.dependency_confusion:DependencyConfusionScanner",
        worker_note="Checking for dependency confusion vulnerabilities...",
        requires_http=True,
        finding_module=True,
        extractor="generic",
        passive=False,
    )),
    ("graphql_scanner", ModuleDef(
        name="graphql_scanner",
        label="GraphQL Security",
        label_de="GraphQL-Sicherheit",
        category="active",
        module_path="yads.modules.graphql_scanner:GraphQlScanner",
        worker_note="Testing GraphQL endpoint security...",
        requires_http=True,
        finding_module=True,
        extractor="generic",
        passive=False,
    )),
    ("websocket_scanner", ModuleDef(
        name="websocket_scanner",
        label="WebSocket Security",
        label_de="WebSocket-Sicherheit",
        category="active",
        module_path="yads.modules.websocket_scanner:WebSocketScanner",
        worker_note="Scanning WebSocket endpoints for vulnerabilities...",
        requires_http=True,
        finding_module=True,
        extractor="generic",
        passive=False,
    )),
    ("password_spray_mapper", ModuleDef(
        name="password_spray_mapper",
        label="Password Spray Surface",
        label_de="Passwort-Spray-Angriffsfläche",
        category="threat",
        module_path="yads.modules.password_spray_mapper:PasswordSprayMapper",
        worker_note="Mapping password spray attack surface...",
        requires_http=True,
        finding_module=True,
        extractor="generic",
    )),
    ("leaked_credentials", ModuleDef(
        name="leaked_credentials",
        label="Leaked Credentials",
        label_de="Gestohlene Zugangsdaten",
        category="threat",
        module_path="yads.modules.leaked_credentials:LeakedCredentialsScanner",
        worker_note="Checking breach databases for leaked credentials...",
        finding_module=True,
        extractor="generic",
    )),
    ("leak_monitor", ModuleDef(
        name="leak_monitor",
        label="Leak Monitor",
        label_de="Leak-Monitor",
        category="exposure",
        module_path="yads.modules.leak_monitor:LeakMonitor",
        worker_note="Checking emails against Have I Been Pwned breach database...",
        finding_module=True,
        extractor="generic",
        passive=False,
    )),
    ("tech_stack_analyzer", ModuleDef(
        name="tech_stack_analyzer",
        label="Tech Stack Analyzer",
        label_de="Tech-Stack-Analyse",
        category="web",
        module_path="yads.modules.tech_stack_analyzer:TechStackAnalyzer",
        worker_note="Fingerprinting technology stack, frameworks and versions...",
        finding_module=True,
        extractor="generic",
        passive=False,
    )),
    ("whois_history_scanner", ModuleDef(
        name="whois_history_scanner",
        label="WHOIS History",
        label_de="WHOIS-Verlauf",
        category="recon",
        module_path="yads.modules.whois_history_scanner:WhoisHistoryScanner",
        worker_note="Fetching WHOIS registration history and ownership data...",
        finding_module=True,
        extractor="generic",
        passive=True,
    )),
    ("dns_cleanup", ModuleDef(
        name="dns_cleanup",
        label="DNS Cleanup Scanner",
        label_de="DNS-Bereinigungsscanner",
        category="recon",
        module_path="yads.modules.dns_cleanup_scanner:DNSCleanupScanner",
        worker_note="Resolving DNS records, detecting dead/parked domains...",
        finding_module=False,
        extractor="generic",
        passive=False,
    )),
    ("api_security_scanner", ModuleDef(
        name="api_security_scanner",
        label="API Security",
        label_de="API-Sicherheit",
        category="active",
        module_path="yads.modules.api_security_scanner:ApiSecurityScanner",
        worker_note="Testing API endpoint security (OWASP API Top 10)...",
        requires_http=True,
        finding_module=True,
        extractor="generic",
        passive=False,
    )),
    ("mobile_app_discovery", ModuleDef(
        name="mobile_app_discovery",
        label="Mobile App Discovery",
        label_de="Mobile-App-Erkennung",
        category="recon",
        module_path="yads.modules.mobile_app_discovery:MobileAppDiscovery",
        worker_note="Discovering associated mobile apps and deep links...",
        finding_module=True,
        extractor="generic",
    )),

    # ── OSINT (not shown in main scan UI but registered for labels/findings) ─
    ("api_discovery", ModuleDef(
        name="api_discovery",
        label="API Discovery",
        label_de="API-Erkennung",
        category="active",
        module_path="yads.modules.api_discovery:ApiDiscoveryScanner",
        worker_note="Running API discovery...",
        requires_http=True,
        # New/vanished endpoint findings (#63) are the only thing surfaced —
        # see the narrowly-scoped api_discovery branch in security_findings.py.
        finding_module=True,
    )),
    ("form_discovery", ModuleDef(
        name="form_discovery",
        label="Form Discovery",
        label_de="Formular-Erkennung",
        category="active",
        module_path="yads.modules.form_discovery:FormDiscoveryScanner",
        worker_note="Discovering forms and input surfaces...",
        requires_http=True,
        finding_module=False,
    )),
    ("brand_intelligence", ModuleDef(
        name="brand_intelligence",
        label="Brand Intelligence",
        label_de="Marken-Intelligence",
        category="threat",
        module_path="yads.modules.brand_intelligence:BrandIntelligenceScanner",
        worker_note="Running brand intelligence analysis...",
        finding_module=False,
    )),
    ("email_intelligence", ModuleDef(
        name="email_intelligence",
        label="Email Intelligence",
        label_de="E-Mail-Intelligence",
        category="threat",
        module_path="yads.modules.email_intelligence:EmailIntelligenceScanner",
        worker_note="Running email intelligence analysis...",
        finding_module=False,
    )),
    ("social_media_scanner", ModuleDef(
        name="social_media_scanner",
        label="Social Media",
        label_de="Social Media",
        category="threat",
        module_path="yads.modules.social_media_scanner:SocialMediaScanner",
        worker_note="Scanning social media presence...",
        finding_module=False,
    )),
    ("analytics_correlator", ModuleDef(
        name="analytics_correlator",
        label="Analytics Correlator",
        label_de="Analytics-Korrelation",
        category="active",
        module_path="yads.modules.analytics_correlator:AnalyticsCorrelator",
        worker_note="Running analytics correlation...",
        finding_module=False,
        custom_dispatch=True,
    )),
    ("quick_web_probe", ModuleDef(
        name="quick_web_probe",
        label="Quick Web Probe",
        label_de="Schnell-Web-Probe",
        category="active",
        module_path="yads.modules.port_scanner:PortScanner",
        worker_note="Running quick web probe...",
        finding_module=False,
        custom_dispatch=True,
    )),
])


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------

def get_module(name: str) -> Optional[ModuleDef]:
    return REGISTRY.get(name)


def get_label(name: str, lang: str = "en") -> str:
    """Return display label for a module name."""
    defn = REGISTRY.get(name)
    if not defn:
        return name
    return defn.label_de if lang == "de" else defn.label


def get_finding_modules() -> List[str]:
    """Return module names included in the security findings aggregation."""
    return [name for name, defn in REGISTRY.items() if defn.finding_module]


def get_simple_dispatch_modules() -> List[ModuleDef]:
    """Return modules that use standard _run_simple_module dispatch (no custom logic)."""
    return [defn for defn in REGISTRY.values() if not defn.custom_dispatch and defn.module_path]


def get_scan_categories(prefix: str = "sc", enabled_modules: Optional[set] = None) -> List[Dict]:
    """
    Return categorized module structure for scan type UI.
    Used by target_detail and target_table templates.

    prefix: CSS group prefix ("sc" for target_detail, "t" for target_table)
    enabled_modules: optional set of module names enabled for this tenant (None = all enabled)
    """
    # Modules to show in the scan UI (exclude OSINT-only/internal)
    UI_MODULES = {
        "subdomain_scanner", "dns_scanner", "axfr_scanner", "tld_scanner",
        "typosquat_scanner", "rpki_scanner",
        "web_analyzer", "ssl_scanner", "http_headers", "cookie_scanner",
        "cors_scanner", "csp_scanner", "security_txt", "cert_mismatch",
        "email_security", "dsgvo_scanner", "git_exposure", "seed_files_scanner",
        "metadata_scanner",
        "shodan_censys", "js_secrets", "wayback_scanner", "external_resources",
        "cloud_scanner",
        "threat_intel", "subdomain_takeover", "nuclei_scanner", "banner_grabber",
        "port_scanner", "nmap_scanner", "crawler", "content_discovery",
        "visual_osint", "deception_detector", "infrastructure_scanner",
        "ipv6_scanner", "open_redirect_scanner", "dns_history_scanner",
        "asn_scanner", "login_scanner", "waf_detector",
        "phishing_scanner", "tls_deep_scanner",
        "ct_monitor", "email_harvester", "dependency_confusion",
        "graphql_scanner", "websocket_scanner",
        "password_spray_mapper", "leaked_credentials",
        "api_security_scanner", "mobile_app_discovery",
    }
    # Also include any dynamically installed custom modules
    UI_MODULES = UI_MODULES | {
        name for name, defn in REGISTRY.items()
        if name not in UI_MODULES and getattr(defn, "custom_dispatch", False) is False
        and name not in {
            "api_discovery", "form_discovery", "brand_intelligence",
            "email_intelligence", "social_media_scanner", "analytics_correlator",
            "quick_web_probe",
        }
    }

    result = []
    for cat in CATEGORIES:
        cat_id = cat["id"]
        group_id = f"{prefix}-{cat_id}"
        modules = [
            defn for defn in REGISTRY.values()
            if defn.category == cat_id
            and defn.name in UI_MODULES
            and (enabled_modules is None or defn.name in enabled_modules)
        ]
        if modules:
            result.append({
                "id": cat_id,
                "group_id": group_id,
                "label": cat["label"],
                "label_de": cat["label_de"],
                "color": cat["color"],
                "modules": modules,
            })
    return result


def get_module_labels() -> Dict[str, str]:
    """Return {module_name: English label} for all registered modules."""
    return {name: defn.label for name, defn in REGISTRY.items()}


def get_unavailable_modules() -> set:
    """
    Return set of module names whose required binary is not present on this system.
    These modules are fully disabled in the UI (checkbox greyed/disabled).
    """
    import shutil
    unavailable = set()
    for name, defn in REGISTRY.items():
        if defn.requires_binary and not shutil.which(defn.requires_binary):
            unavailable.add(name)
    return unavailable


def get_degraded_modules() -> set:
    """
    Return set of module names that are present but running in fallback/limited mode
    because their preferred binary is missing. UI shows a "limited mode" badge.
    """
    import shutil
    degraded = set()
    for name, defn in REGISTRY.items():
        if defn.degraded_without_binary and not shutil.which(defn.degraded_without_binary):
            degraded.add(name)
    return degraded

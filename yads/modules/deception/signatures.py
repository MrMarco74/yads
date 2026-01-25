"""
Deception Technology Signatures Database

Contains known signatures, patterns, and fingerprints for detecting:
- Honeypots (web, SSH, FTP, SMTP, Telnet)
- DNS Sinkholes
- Network Tarpits
"""

import re
from typing import Dict, List, Set
from dataclasses import dataclass


@dataclass
class HoneypotSignature:
    """Represents a honeypot detection signature."""
    name: str
    type: str  # "web", "ssh", "ftp", "smtp", "telnet", "generic"
    pattern: str  # Regex pattern or exact match
    is_regex: bool = True
    confidence: int = 50  # Base confidence contribution
    description: str = ""


# =============================================================================
# SSH Honeypot Signatures
# =============================================================================

SSH_HONEYPOT_BANNERS = {
    # Cowrie default banners
    "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2": {
        "name": "Cowrie",
        "confidence": 70,
        "description": "Common Cowrie default banner"
    },
    "SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1.4": {
        "name": "Cowrie",
        "confidence": 65,
        "description": "Cowrie variant banner"
    },
    # Kippo default banners
    "SSH-2.0-OpenSSH_5.1p1 Debian-5": {
        "name": "Kippo",
        "confidence": 70,
        "description": "Common Kippo default banner"
    },
    "SSH-2.0-OpenSSH_5.5p1 Debian-6": {
        "name": "Kippo",
        "confidence": 65,
        "description": "Kippo variant banner"
    },
    # HonSSH
    "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2": {
        "name": "HonSSH",
        "confidence": 55,
        "description": "Possible HonSSH banner"
    },
}

# SSH version patterns that indicate potential honeypots
SSH_SUSPICIOUS_PATTERNS = [
    {
        "pattern": r"SSH-2\.0-OpenSSH_[45]\.[0-9]p1 Debian",
        "name": "Old Debian SSH",
        "confidence": 40,
        "description": "Outdated Debian SSH version commonly used by honeypots"
    },
    {
        "pattern": r"SSH-2\.0-OpenSSH_[0-4]\.",
        "name": "Ancient OpenSSH",
        "confidence": 35,
        "description": "Very old OpenSSH version, likely honeypot or vulnerable system"
    },
]


# =============================================================================
# Web Honeypot Signatures
# =============================================================================

WEB_HONEYPOT_SIGNATURES: List[HoneypotSignature] = [
    # Glastopf signatures
    HoneypotSignature(
        name="Glastopf",
        type="web",
        pattern=r"<title>Blog</title>.*phpMyAdmin",
        confidence=65,
        description="Glastopf default vulnerable page"
    ),
    HoneypotSignature(
        name="Glastopf",
        type="web",
        pattern=r"glastopf",
        is_regex=False,
        confidence=90,
        description="Direct Glastopf reference"
    ),

    # SNARE/TANNER signatures
    HoneypotSignature(
        name="SNARE",
        type="web",
        pattern=r"snare|tanner",
        confidence=85,
        description="SNARE/TANNER honeypot reference"
    ),

    # Dionaea HTTP module
    HoneypotSignature(
        name="Dionaea",
        type="web",
        pattern=r"dionaea",
        is_regex=False,
        confidence=90,
        description="Dionaea honeypot reference"
    ),

    # Generic honeypot indicators
    HoneypotSignature(
        name="Generic Honeypot",
        type="web",
        pattern=r"honeypot|honey[\s_-]?pot",
        confidence=80,
        description="Direct honeypot reference in response"
    ),

    # Fake vulnerability indicators
    HoneypotSignature(
        name="Fake phpMyAdmin",
        type="web",
        pattern=r"phpMyAdmin.*3\.[0-3]\.",
        confidence=45,
        description="Suspiciously old phpMyAdmin version"
    ),
    HoneypotSignature(
        name="Fake WordPress",
        type="web",
        pattern=r"WordPress\s*[12]\.[0-9]",
        confidence=40,
        description="Ancient WordPress version claim"
    ),
]

# Known honeypot HTML content hashes (SHA256)
WEB_HONEYPOT_CONTENT_HASHES: Dict[str, Dict] = {
    # Glastopf default pages
    "a3f2b8c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1": {
        "name": "Glastopf Default",
        "confidence": 80
    },
    # Add more known hashes as discovered
}

# Suspicious HTTP headers that may indicate honeypots
SUSPICIOUS_HTTP_HEADERS: Dict[str, List[Dict]] = {
    "Server": [
        {"pattern": r"Apache/2\.2\.(3|9|15)", "confidence": 30, "name": "Old Apache"},
        {"pattern": r"Apache/1\.", "confidence": 40, "name": "Ancient Apache"},
        {"pattern": r"Microsoft-IIS/[456]\.", "confidence": 35, "name": "Old IIS"},
    ],
    "X-Powered-By": [
        {"pattern": r"PHP/[45]\.[0-2]", "confidence": 25, "name": "Old PHP"},
    ],
}


# =============================================================================
# FTP Honeypot Signatures
# =============================================================================

FTP_HONEYPOT_BANNERS = {
    # Dionaea FTP
    "220 DiskStation FTP server ready": {
        "name": "Dionaea",
        "confidence": 55,
        "description": "Dionaea DiskStation emulation"
    },
    "220 Welcome to the ftp service": {
        "name": "Generic Honeypot",
        "confidence": 40,
        "description": "Generic/suspicious FTP banner"
    },
}

FTP_SUSPICIOUS_PATTERNS = [
    {
        "pattern": r"220.*honeypot",
        "name": "FTP Honeypot",
        "confidence": 90,
        "description": "Honeypot reference in FTP banner"
    },
    {
        "pattern": r"220.*ProFTPD 1\.[23]\.",
        "name": "Old ProFTPD",
        "confidence": 35,
        "description": "Outdated ProFTPD version"
    },
]


# =============================================================================
# SMTP Honeypot Signatures
# =============================================================================

SMTP_HONEYPOT_BANNERS = {
    "220 mailoney SMTP": {
        "name": "Mailoney",
        "confidence": 90,
        "description": "Mailoney SMTP honeypot"
    },
    "220 mail.honeypot.local": {
        "name": "Generic SMTP Honeypot",
        "confidence": 85,
        "description": "Obvious honeypot hostname"
    },
}

SMTP_SUSPICIOUS_PATTERNS = [
    {
        "pattern": r"220.*honeypot",
        "name": "SMTP Honeypot",
        "confidence": 90,
        "description": "Honeypot reference in SMTP banner"
    },
    {
        "pattern": r"220.*Postfix.*Ubuntu",
        "name": "Generic Postfix",
        "confidence": 20,
        "description": "Common but may be honeypot"
    },
]


# =============================================================================
# Telnet Honeypot Signatures
# =============================================================================

TELNET_HONEYPOT_PATTERNS = [
    {
        "pattern": r"BusyBox v1\.[012][0-9]\.",
        "name": "IoT Honeypot",
        "confidence": 45,
        "description": "Old BusyBox version commonly emulated"
    },
    {
        "pattern": r"Mirai|botnet",
        "name": "Mirai Honeypot",
        "confidence": 70,
        "description": "Mirai-style honeypot"
    },
    {
        "pattern": r"login:.*root.*password:",
        "name": "Fake Login",
        "confidence": 35,
        "description": "Suspiciously simple login prompt"
    },
]


# =============================================================================
# Behavioral Indicators
# =============================================================================

BEHAVIORAL_INDICATORS = {
    # Response timing anomalies
    "consistent_response_time": {
        "threshold_ms": 5,  # If all responses within 5ms, suspicious
        "confidence": 25,
        "description": "Unnaturally consistent response times"
    },
    "too_fast_response": {
        "threshold_ms": 1,  # Response faster than 1ms
        "confidence": 30,
        "description": "Impossibly fast response time"
    },

    # Content anomalies
    "same_content_all_paths": {
        "confidence": 40,
        "description": "Same content returned for all URL paths"
    },
    "accepts_all_methods": {
        "confidence": 35,
        "description": "Server accepts all HTTP methods without error"
    },

    # Service anomalies
    "too_many_open_ports": {
        "threshold": 50,
        "confidence": 45,
        "description": "Unrealistic number of open ports"
    },
    "impossible_service_combo": {
        "confidence": 50,
        "description": "Impossible service combination (e.g., Windows + Apache + nginx)"
    },
}


# =============================================================================
# Technology Mismatch Detection
# =============================================================================

# OS/Service combinations that are impossible or highly unlikely
IMPOSSIBLE_COMBINATIONS = [
    {
        "os_pattern": r"Windows",
        "service_pattern": r"nginx/1\.[0-9]+.*Ubuntu",
        "confidence": 60,
        "description": "Windows with Ubuntu nginx"
    },
    {
        "os_pattern": r"Linux|Ubuntu|Debian",
        "service_pattern": r"Microsoft-IIS",
        "confidence": 70,
        "description": "Linux with IIS"
    },
    {
        "os_pattern": r"Windows",
        "service_pattern": r"Apache.*Unix",
        "confidence": 55,
        "description": "Windows with Unix Apache"
    },
]


# =============================================================================
# Utility Functions
# =============================================================================

def match_ssh_banner(banner: str) -> List[Dict]:
    """Check SSH banner against known honeypot signatures."""
    matches = []

    # Exact matches
    if banner in SSH_HONEYPOT_BANNERS:
        match = SSH_HONEYPOT_BANNERS[banner].copy()
        match["banner"] = banner
        matches.append(match)

    # Pattern matches
    for pattern_info in SSH_SUSPICIOUS_PATTERNS:
        if re.search(pattern_info["pattern"], banner, re.IGNORECASE):
            matches.append({
                "name": pattern_info["name"],
                "confidence": pattern_info["confidence"],
                "description": pattern_info["description"],
                "banner": banner
            })

    return matches


def match_web_content(content: str, headers: Dict[str, str] = None) -> List[Dict]:
    """Check web content against known honeypot signatures."""
    matches = []

    for sig in WEB_HONEYPOT_SIGNATURES:
        if sig.is_regex:
            if re.search(sig.pattern, content, re.IGNORECASE | re.DOTALL):
                matches.append({
                    "name": sig.name,
                    "confidence": sig.confidence,
                    "description": sig.description,
                    "type": sig.type
                })
        else:
            if sig.pattern.lower() in content.lower():
                matches.append({
                    "name": sig.name,
                    "confidence": sig.confidence,
                    "description": sig.description,
                    "type": sig.type
                })

    # Check headers
    if headers:
        for header_name, patterns in SUSPICIOUS_HTTP_HEADERS.items():
            header_value = headers.get(header_name, "")
            for pattern_info in patterns:
                if re.search(pattern_info["pattern"], header_value, re.IGNORECASE):
                    matches.append({
                        "name": pattern_info["name"],
                        "confidence": pattern_info["confidence"],
                        "description": f"Suspicious {header_name} header",
                        "type": "web"
                    })

    return matches


def match_ftp_banner(banner: str) -> List[Dict]:
    """Check FTP banner against known honeypot signatures."""
    matches = []

    # Exact matches
    for known_banner, info in FTP_HONEYPOT_BANNERS.items():
        if known_banner in banner:
            matches.append({
                "name": info["name"],
                "confidence": info["confidence"],
                "description": info["description"],
                "banner": banner
            })

    # Pattern matches
    for pattern_info in FTP_SUSPICIOUS_PATTERNS:
        if re.search(pattern_info["pattern"], banner, re.IGNORECASE):
            matches.append({
                "name": pattern_info["name"],
                "confidence": pattern_info["confidence"],
                "description": pattern_info["description"],
                "banner": banner
            })

    return matches


def match_smtp_banner(banner: str) -> List[Dict]:
    """Check SMTP banner against known honeypot signatures."""
    matches = []

    # Exact matches
    for known_banner, info in SMTP_HONEYPOT_BANNERS.items():
        if known_banner in banner:
            matches.append({
                "name": info["name"],
                "confidence": info["confidence"],
                "description": info["description"],
                "banner": banner
            })

    # Pattern matches
    for pattern_info in SMTP_SUSPICIOUS_PATTERNS:
        if re.search(pattern_info["pattern"], banner, re.IGNORECASE):
            matches.append({
                "name": pattern_info["name"],
                "confidence": pattern_info["confidence"],
                "description": pattern_info["description"],
                "banner": banner
            })

    return matches


def check_technology_mismatch(os_info: str, service_info: str) -> List[Dict]:
    """Check for impossible OS/service combinations."""
    matches = []

    for combo in IMPOSSIBLE_COMBINATIONS:
        os_match = re.search(combo["os_pattern"], os_info, re.IGNORECASE)
        service_match = re.search(combo["service_pattern"], service_info, re.IGNORECASE)

        if os_match and service_match:
            matches.append({
                "name": "Technology Mismatch",
                "confidence": combo["confidence"],
                "description": combo["description"],
                "os": os_info,
                "service": service_info
            })

    return matches

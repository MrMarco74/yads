"""
External Scanner Import Router (#53)

Imports findings from external security tools:
  - Burp Suite (XML export)
  - Nessus (.nessus XML)
  - OpenVAS / GVM (XML)
  - Qualys (XML)
  - OWASP ZAP (XML/JSON)
  - Nuclei (JSON)
  - Generic JSON findings format

Creates ScanResult entries in the database so findings are visible in YADS UI.
"""

import io
import json
import logging
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select

from yads.api.templating import templates
from yads.auth.deps import RoleChecker
from yads.database import get_session
from yads.models import ScanResult, Target, ModuleState, User
from yads.utils.sanitize import sanitize_null_bytes

logger = logging.getLogger(__name__)

router = APIRouter()

SEVERITY_MAP = {
    # Nessus
    "0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical",
    # Text forms
    "informational": "info", "info": "info",
    "low": "low", "medium": "medium", "high": "high", "critical": "critical",
    "none": "info",
    # CVSS-based
    "0": "info",
}


def _normalize_severity(raw: str) -> str:
    return SEVERITY_MAP.get(str(raw).lower().strip(), "medium")


# ─────────────────────────────────────────
# Parsers
# ─────────────────────────────────────────

def _parse_burp(xml_content: bytes) -> List[Dict]:
    """Parse Burp Suite XML export."""
    findings = []
    try:
        root = ET.fromstring(xml_content)
        for issue in root.findall(".//issue"):
            name = (issue.findtext("name") or "").strip()
            severity = _normalize_severity(issue.findtext("severity") or "medium")
            confidence = (issue.findtext("confidence") or "").strip()
            host = (issue.findtext("host") or "").strip()
            path = (issue.findtext("path") or "").strip()
            detail = (issue.findtext("issueDetail") or "").strip()
            background = (issue.findtext("issueBackground") or "").strip()
            remediation = (issue.findtext("remediationBackground") or "").strip()

            findings.append({
                "title": name,
                "severity": severity,
                "description": detail or background,
                "remediation": remediation,
                "url": f"{host}{path}" if host else path,
                "confidence": confidence,
                "source": "burp",
            })
    except Exception as e:
        logger.warning(f"Burp parse error: {e}")
    return findings


def _parse_nessus(xml_content: bytes) -> List[Dict]:
    """Parse Nessus .nessus XML format."""
    findings = []
    try:
        root = ET.fromstring(xml_content)
        for host in root.findall(".//ReportHost"):
            hostname = host.get("name", "")
            for item in host.findall(".//ReportItem"):
                plugin_name = item.get("pluginName", "")
                severity_num = item.get("severity", "0")
                port = item.get("port", "")
                protocol = item.get("protocol", "tcp")
                description = (item.findtext("description") or "").strip()
                solution = (item.findtext("solution") or "").strip()
                synopsis = (item.findtext("synopsis") or "").strip()
                cvss_base = item.findtext("cvss_base_score") or ""
                cve_list = [c.text for c in item.findall("cve") if c.text]

                if severity_num == "0":
                    continue  # Skip info-level Nessus findings by default

                findings.append({
                    "title": plugin_name,
                    "severity": _normalize_severity(severity_num),
                    "description": synopsis or description,
                    "remediation": solution,
                    "url": f"{hostname}:{port}/{protocol}" if port else hostname,
                    "cvss": cvss_base,
                    "cves": cve_list[:5],
                    "source": "nessus",
                })
    except Exception as e:
        logger.warning(f"Nessus parse error: {e}")
    return findings


def _parse_openvas(xml_content: bytes) -> List[Dict]:
    """Parse OpenVAS/GVM XML report."""
    findings = []
    try:
        root = ET.fromstring(xml_content)
        for result in root.findall(".//result"):
            name = (result.findtext("name") or "").strip()
            threat = (result.findtext("threat") or "low").strip()
            description = (result.findtext("description") or "").strip()
            host_elem = result.find("host")
            host = host_elem.text.strip() if host_elem is not None and host_elem.text else ""
            port_elem = result.find("port")
            port = port_elem.text.strip() if port_elem is not None and port_elem.text else ""
            nvt = result.find("nvt")
            cvss = ""
            solution = ""
            if nvt is not None:
                cvss = nvt.findtext("cvss_base") or ""
                solution = nvt.findtext("solution") or ""

            if threat.lower() == "log":
                continue

            findings.append({
                "title": name,
                "severity": _normalize_severity(threat),
                "description": description,
                "remediation": solution,
                "url": f"{host}:{port}" if port and port != "general/tcp" else host,
                "cvss": cvss,
                "source": "openvas",
            })
    except Exception as e:
        logger.warning(f"OpenVAS parse error: {e}")
    return findings


def _parse_zap(content: bytes) -> List[Dict]:
    """Parse OWASP ZAP XML or JSON."""
    findings = []
    # Try JSON first
    try:
        data = json.loads(content)
        alerts = data.get("site", [{}])[0].get("alerts", []) if isinstance(data.get("site"), list) else []
        for alert in alerts:
            findings.append({
                "title": alert.get("alert", ""),
                "severity": _normalize_severity(alert.get("riskdesc", "medium").split()[0]),
                "description": alert.get("desc", ""),
                "remediation": alert.get("solution", ""),
                "url": alert.get("instances", [{}])[0].get("uri", "") if alert.get("instances") else "",
                "source": "zap",
            })
        return findings
    except Exception:
        pass
    # Try XML
    try:
        root = ET.fromstring(content)
        for alert in root.findall(".//alertitem"):
            findings.append({
                "title": (alert.findtext("alert") or "").strip(),
                "severity": _normalize_severity(alert.findtext("riskdesc") or "medium"),
                "description": (alert.findtext("desc") or "").strip(),
                "remediation": (alert.findtext("solution") or "").strip(),
                "url": (alert.findtext("uri") or "").strip(),
                "source": "zap",
            })
    except Exception as e:
        logger.warning(f"ZAP parse error: {e}")
    return findings


def _parse_nuclei_json(content: bytes) -> List[Dict]:
    """Parse Nuclei JSON output (newline-delimited or array)."""
    findings = []
    try:
        text = content.decode("utf-8", errors="replace")
        results = []
        # Try array first
        try:
            results = json.loads(text)
        except Exception:
            # NDJSON
            for line in text.splitlines():
                line = line.strip()
                if line:
                    try:
                        results.append(json.loads(line))
                    except Exception:
                        pass

        for r in results:
            findings.append({
                "title": f"[{r.get('template-id', '')}] {r.get('info', {}).get('name', '')}",
                "severity": _normalize_severity(r.get("info", {}).get("severity", "medium")),
                "description": r.get("info", {}).get("description", ""),
                "remediation": r.get("info", {}).get("remediation", ""),
                "url": r.get("matched-at") or r.get("host", ""),
                "tags": r.get("info", {}).get("tags", []),
                "cves": r.get("info", {}).get("classification", {}).get("cve-id", []),
                "source": "nuclei",
            })
    except Exception as e:
        logger.warning(f"Nuclei JSON parse error: {e}")
    return findings


def _parse_generic_json(content: bytes) -> List[Dict]:
    """Parse generic YADS JSON findings format."""
    findings = []
    try:
        data = json.loads(content)
        items = data if isinstance(data, list) else data.get("findings", [])
        for item in items:
            findings.append({
                "title": item.get("title", "Unnamed finding"),
                "severity": _normalize_severity(item.get("severity", "medium")),
                "description": item.get("description", ""),
                "remediation": item.get("remediation", ""),
                "url": item.get("url", ""),
                "source": "generic",
            })
    except Exception as e:
        logger.warning(f"Generic JSON parse error: {e}")
    return findings


def _detect_format(filename: str, content: bytes) -> str:
    """Auto-detect scanner format from filename and content."""
    name_lower = filename.lower()
    if name_lower.endswith(".nessus") or b"NessusClientData_v2" in content[:200]:
        return "nessus"
    if b"<BurpSuite" in content[:200] or b"<issue>" in content[:500]:
        return "burp"
    if b"<report" in content[:200] and b"<nvt" in content[:1000]:
        return "openvas"
    if b"<OWASPZAPReport" in content[:200] or b"<alertitem" in content[:1000]:
        return "zap"
    if name_lower.endswith(".json"):
        try:
            data = json.loads(content[:2000])
            if isinstance(data, list) and data and "template-id" in str(data[0]):
                return "nuclei"
            return "generic_json"
        except Exception:
            # Try NDJSON
            first_line = content.split(b"\n")[0]
            try:
                obj = json.loads(first_line)
                if "template-id" in obj:
                    return "nuclei"
            except Exception:
                pass
    return "unknown"


def _parse_content(fmt: str, content: bytes) -> List[Dict]:
    parsers = {
        "burp": _parse_burp,
        "nessus": _parse_nessus,
        "openvas": _parse_openvas,
        "zap": _parse_zap,
        "nuclei": _parse_nuclei_json,
        "generic_json": _parse_generic_json,
    }
    parser = parsers.get(fmt)
    if not parser:
        return []
    return parser(content)


def _save_import_result(
    session: Session,
    target: Target,
    findings: List[Dict],
    source_format: str,
    filename: str,
    user: User,
) -> ScanResult:
    """Save imported findings as a ScanResult."""
    now = datetime.utcnow()
    data = {
        "domain": target.domain,
        "imported_from": source_format,
        "import_file": filename,
        "imported_at": now.isoformat(),
        "imported_by": user.username if hasattr(user, "username") else str(user.id),
        "findings": findings,
        "summary": {
            "total": len(findings),
            "critical": len([f for f in findings if f["severity"] == "critical"]),
            "high": len([f for f in findings if f["severity"] == "high"]),
            "medium": len([f for f in findings if f["severity"] == "medium"]),
            "low": len([f for f in findings if f["severity"] == "low"]),
            "info": len([f for f in findings if f["severity"] == "info"]),
        },
    }
    data = sanitize_null_bytes(data)

    module_name = f"import_{source_format}"
    sr = ScanResult(
        target_id=target.id,
        module_name=module_name,
        data=data,
        created_at=now,
        tenant_id=target.tenant_id,
    )
    session.add(sr)
    session.commit()
    session.refresh(sr)
    return sr


# ─────────────────────────────────────────
# Routes
# ─────────────────────────────────────────

@router.get("/scanner-import", response_class=HTMLResponse)
async def import_page(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"])),
):
    # Get targets for this tenant
    targets = session.exec(
        select(Target).where(Target.tenant_id == user.tenant_id, Target.is_archived == False)
        .order_by(Target.domain)
    ).all()
    return templates.TemplateResponse("scanner_import.html", {
        "request": request,
        "user": user,
        "targets": targets,
        "page_title": "Import External Scanner Results",
    })


@router.post("/scanner-import/upload", response_class=HTMLResponse)
async def import_upload(
    request: Request,
    target_id: int = Form(...),
    format_hint: str = Form(default="auto"),
    file_upload: UploadFile = File(...),
    session: Session = Depends(get_session),
    user: User = Depends(RoleChecker(["admin", "tenant_admin", "scanner"])),
):
    target = session.exec(
        select(Target).where(Target.id == target_id, Target.tenant_id == user.tenant_id)
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    content = await file_upload.read()
    if len(content) > 50 * 1024 * 1024:  # 50 MB limit
        raise HTTPException(status_code=413, detail="File too large (max 50 MB)")

    filename = file_upload.filename or "upload"
    detected_fmt = _detect_format(filename, content) if format_hint == "auto" else format_hint

    findings = _parse_content(detected_fmt, content)
    if not findings:
        return templates.TemplateResponse("scanner_import.html", {
            "request": request,
            "user": user,
            "targets": session.exec(select(Target).where(Target.tenant_id == user.tenant_id)).all(),
            "page_title": "Import External Scanner Results",
            "error": f"No findings could be parsed from '{filename}'. Detected format: {detected_fmt}. "
                     "Check that the file matches a supported format.",
        })

    sr = _save_import_result(session, target, findings, detected_fmt, filename, user)

    return RedirectResponse(
        url=f"/targets/{target.id}?msg=Imported+{len(findings)}+findings+from+{filename}",
        status_code=303,
    )

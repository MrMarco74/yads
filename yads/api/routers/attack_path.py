"""
Attack Path Visualizer (#45)

Builds a graph of potential attack chains for a given target by aggregating
data from all available scan results. Nodes represent assets, services, ports,
and findings. Edges represent exploitable relationships between them.
"""
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlmodel import Session, select

from yads.api.templating import templates
from yads.auth.deps import get_current_active_user, get_current_user_html
from yads.database import get_session
from yads.models import ScanResult, Target, User

router = APIRouter(tags=["attack-path"])

# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

SEVERITY_RISK: Dict[str, int] = {
    "critical": 10,
    "high": 8,
    "medium": 5,
    "low": 3,
    "info": 1,
}


def _risk(severity: str) -> int:
    return SEVERITY_RISK.get((severity or "info").lower(), 1)


# ---------------------------------------------------------------------------
# Graph builders per module
# ---------------------------------------------------------------------------

def _build_port_nodes(
    target_node_id: str,
    data: Dict,
    nodes: List[Dict],
    edges: List[Dict],
    node_ids: set,
) -> List[str]:
    """Extract open ports and create port nodes linked to the target."""
    port_node_ids: List[str] = []
    raw_ports = data.get("open_ports", [])
    if not isinstance(raw_ports, list):
        return port_node_ids

    for p in raw_ports:
        port_num: Optional[int] = None
        service_name: Optional[str] = None
        banner: Optional[str] = None

        if isinstance(p, int):
            port_num = p
        elif isinstance(p, dict):
            port_num = p.get("port")
            service_name = p.get("service") or p.get("name")
            banner = p.get("banner") or p.get("version")

        if port_num is None:
            continue

        nid = f"port_{port_num}"
        if nid not in node_ids:
            node_ids.add(nid)
            # Common risky ports get elevated risk
            risk = 3
            if port_num in (21, 22, 23, 3389, 5900, 1433, 3306, 5432, 6379, 27017):
                risk = 6
            elif port_num in (80, 443, 8080, 8443):
                risk = 2

            nodes.append({
                "id": nid,
                "label": f":{port_num}" + (f" ({service_name})" if service_name else ""),
                "type": "port",
                "risk": risk,
                "metadata": {
                    "port": port_num,
                    "service": service_name or "unknown",
                    "banner": banner or "",
                },
            })
            edges.append({
                "source": target_node_id,
                "target": nid,
                "label": "exposes",
            })

        port_node_ids.append(nid)

    # Also handle legacy http/https keys
    if data.get("http", {}).get("open") and "port_80" not in node_ids:
        nid = "port_80"
        node_ids.add(nid)
        nodes.append({"id": nid, "label": ":80 (http)", "type": "port", "risk": 2,
                       "metadata": {"port": 80, "service": "http", "banner": ""}})
        edges.append({"source": target_node_id, "target": nid, "label": "exposes"})
        port_node_ids.append(nid)

    if data.get("https", {}).get("open") and "port_443" not in node_ids:
        nid = "port_443"
        node_ids.add(nid)
        nodes.append({"id": nid, "label": ":443 (https)", "type": "port", "risk": 2,
                       "metadata": {"port": 443, "service": "https", "banner": ""}})
        edges.append({"source": target_node_id, "target": nid, "label": "exposes"})
        port_node_ids.append(nid)

    return port_node_ids


def _build_service_nodes(
    port_node_ids: List[str],
    data: Dict,
    nodes: List[Dict],
    edges: List[Dict],
    node_ids: set,
) -> List[str]:
    """Extract detected technologies and link them to port nodes (or target)."""
    service_node_ids: List[str] = []
    technologies = data.get("technologies") or data.get("tech_stack") or []
    if not isinstance(technologies, list):
        return service_node_ids

    # Connect services to port 80/443 if available, else first available port
    preferred_ports = ["port_443", "port_80", "port_8443", "port_8080"]
    parent = next((p for p in preferred_ports if p in port_node_ids), None)
    if parent is None and port_node_ids:
        parent = port_node_ids[0]

    for tech in technologies:
        if isinstance(tech, str):
            name = tech
            version = None
            cves: List = []
        elif isinstance(tech, dict):
            name = tech.get("name") or tech.get("technology", "Unknown")
            version = tech.get("version")
            cves = tech.get("cves") or []
        else:
            continue

        nid = f"service_{name.lower().replace(' ', '_').replace('.', '_')}"
        if nid not in node_ids:
            node_ids.add(nid)
            risk = 3
            if cves:
                worst_cve_sev = max(
                    (_risk(c.get("severity", "info")) for c in cves if isinstance(c, dict)),
                    default=3,
                )
                risk = worst_cve_sev

            label = name + (f" {version}" if version else "")
            nodes.append({
                "id": nid,
                "label": label,
                "type": "service",
                "risk": risk,
                "metadata": {
                    "name": name,
                    "version": version or "",
                    "cves": cves[:5],  # cap for payload size
                },
            })
            link_from = parent if parent else "target_root"
            edges.append({"source": link_from, "target": nid, "label": "runs"})

        service_node_ids.append(nid)

    return service_node_ids


def _build_finding_nodes(
    module_name: str,
    data: Dict,
    service_node_ids: List[str],
    nodes: List[Dict],
    edges: List[Dict],
    node_ids: set,
) -> List[str]:
    """Extract generic findings and attach them to relevant service/port nodes."""
    finding_node_ids: List[str] = []
    findings = data.get("findings") or []
    if not isinstance(findings, list):
        return finding_node_ids

    for idx, f in enumerate(findings):
        if not isinstance(f, dict):
            continue

        severity = (f.get("severity") or "info").lower()
        issue = f.get("issue") or f.get("title") or f.get("name") or f.get("type") or "Finding"
        description = f.get("description") or f.get("detail") or ""

        # Unique ID per finding
        safe_issue = issue.lower().replace(" ", "_").replace("/", "_")[:40]
        nid = f"finding_{module_name}_{safe_issue}_{idx}"

        if nid not in node_ids:
            node_ids.add(nid)
            nodes.append({
                "id": nid,
                "label": issue[:60],
                "type": "finding",
                "risk": _risk(severity),
                "metadata": {
                    "severity": severity,
                    "module": module_name,
                    "issue": issue,
                    "description": description[:300],
                },
            })

            # Link finding to a service if possible, else first service, else target
            linked = False
            if service_node_ids:
                edges.append({"source": service_node_ids[0], "target": nid, "label": f"has {severity}"})
                linked = True
            if not linked:
                edges.append({"source": "target_root", "target": nid, "label": f"has {severity}"})

        finding_node_ids.append(nid)

    return finding_node_ids


def _chain_critical_findings(
    finding_node_ids: List[str],
    nodes: List[Dict],
    edges: List[Dict],
) -> None:
    """
    Link critical/high findings together to represent chained attack paths.
    High-severity findings that co-exist imply a multi-step exploitation chain.
    """
    # Build index of high+ findings
    high_plus = [
        nid for nid in finding_node_ids
        if any(n["id"] == nid and n["risk"] >= 8 for n in nodes)
    ]
    # Create directed chain edges between high+ findings
    for i in range(len(high_plus) - 1):
        edges.append({
            "source": high_plus[i],
            "target": high_plus[i + 1],
            "label": "enables",
        })


# ---------------------------------------------------------------------------
# Module-specific extractors for non-findings data
# ---------------------------------------------------------------------------

def _process_nmap_scanner(
    target_node_id: str,
    data: Dict,
    nodes: List[Dict],
    edges: List[Dict],
    node_ids: set,
) -> Tuple[List[str], List[str]]:
    port_ids = _build_port_nodes(target_node_id, data, nodes, edges, node_ids)
    return port_ids, []


def _process_port_scanner(
    target_node_id: str,
    data: Dict,
    nodes: List[Dict],
    edges: List[Dict],
    node_ids: set,
) -> Tuple[List[str], List[str]]:
    port_ids = _build_port_nodes(target_node_id, data, nodes, edges, node_ids)
    return port_ids, []


def _process_web_analyzer(
    target_node_id: str,
    data: Dict,
    nodes: List[Dict],
    edges: List[Dict],
    node_ids: set,
    port_ids: List[str],
) -> Tuple[List[str], List[str]]:
    service_ids = _build_service_nodes(port_ids, data, nodes, edges, node_ids)
    finding_ids = _build_finding_nodes("web_analyzer", data, service_ids, nodes, edges, node_ids)

    # CVEs as findings
    cves = data.get("cves") or []
    for cve in cves:
        if not isinstance(cve, dict):
            continue
        cve_id = cve.get("id") or cve.get("cve_id") or "CVE-UNKNOWN"
        severity = (cve.get("severity") or "medium").lower()
        product = cve.get("product") or ""
        nid = f"finding_cve_{cve_id.lower().replace('-', '_')}"
        if nid not in node_ids:
            node_ids.add(nid)
            nodes.append({
                "id": nid,
                "label": cve_id,
                "type": "finding",
                "risk": _risk(severity),
                "metadata": {
                    "severity": severity,
                    "module": "web_analyzer",
                    "issue": f"{cve_id}: {product}",
                    "description": cve.get("description") or "",
                },
            })
            parent = service_ids[0] if service_ids else target_node_id
            edges.append({"source": parent, "target": nid, "label": f"vuln ({severity})"})
            finding_ids.append(nid)

    return service_ids, finding_ids


def _process_nuclei_scanner(
    data: Dict,
    nodes: List[Dict],
    edges: List[Dict],
    node_ids: set,
    service_ids: List[str],
) -> List[str]:
    finding_ids: List[str] = []
    findings = data.get("findings") or data.get("vulnerabilities") or []
    if not isinstance(findings, list):
        return finding_ids

    for idx, f in enumerate(findings):
        if not isinstance(f, dict):
            continue
        severity = (f.get("severity") or "info").lower()
        name = f.get("name") or f.get("template_id") or f.get("title") or "Nuclei Finding"
        description = f.get("description") or f.get("matcher_name") or ""

        safe = name.lower().replace(" ", "_")[:40]
        nid = f"finding_nuclei_{safe}_{idx}"
        if nid not in node_ids:
            node_ids.add(nid)
            nodes.append({
                "id": nid,
                "label": name[:60],
                "type": "finding",
                "risk": _risk(severity),
                "metadata": {
                    "severity": severity,
                    "module": "nuclei_scanner",
                    "issue": name,
                    "description": description[:300],
                },
            })
            parent = service_ids[0] if service_ids else "target_root"
            edges.append({"source": parent, "target": nid, "label": f"vulnerable ({severity})"})
            finding_ids.append(nid)

    return finding_ids


def _process_ssl_scanner(
    target_node_id: str,
    data: Dict,
    nodes: List[Dict],
    edges: List[Dict],
    node_ids: set,
) -> List[str]:
    finding_ids: List[str] = []
    findings = data.get("findings") or []

    # Also synthesize from ssl-specific fields
    if not findings:
        issues: List[Tuple[str, str]] = []
        grade = (data.get("grade") or "").upper()
        if grade and grade not in ("A", "A+", ""):
            issues.append(("SSL/TLS Grade: " + grade, "medium" if grade in ("B", "C") else "high"))
        if data.get("expired"):
            issues.append(("Certificate Expired", "critical"))
        if data.get("self_signed"):
            issues.append(("Self-Signed Certificate", "high"))
        if data.get("weak_cipher"):
            issues.append(("Weak Cipher Suite", "medium"))

        for issue_text, sev in issues:
            safe = issue_text.lower().replace(" ", "_").replace("/", "_")[:40]
            nid = f"finding_ssl_{safe}"
            if nid not in node_ids:
                node_ids.add(nid)
                nodes.append({
                    "id": nid,
                    "label": issue_text[:60],
                    "type": "finding",
                    "risk": _risk(sev),
                    "metadata": {
                        "severity": sev,
                        "module": "ssl_scanner",
                        "issue": issue_text,
                        "description": "",
                    },
                })
                edges.append({"source": "port_443", "target": nid, "label": f"ssl issue ({sev})"})
                finding_ids.append(nid)
    else:
        finding_ids = _build_finding_nodes("ssl_scanner", data, [], nodes, edges, node_ids)

    return finding_ids


# ---------------------------------------------------------------------------
# Main graph builder
# ---------------------------------------------------------------------------

def build_attack_graph(
    target: Target,
    scan_results: List[ScanResult],
) -> Dict[str, Any]:
    """
    Build a graph dict from all scan results for a target.
    Returns: { nodes, edges, summary }
    """
    nodes: List[Dict] = []
    edges: List[Dict] = []
    node_ids: set = set()

    # Root target node
    target_node_id = "target_root"
    nodes.append({
        "id": target_node_id,
        "label": target.domain,
        "type": "target",
        "risk": 1,
        "metadata": {
            "domain": target.domain,
            "target_id": target.id,
        },
    })
    node_ids.add(target_node_id)

    # Deduplicate — keep latest result per module
    latest: Dict[str, ScanResult] = {}
    for sr in scan_results:
        if sr.module_name not in latest:
            latest[sr.module_name] = sr

    # Aggregate across modules
    all_port_ids: List[str] = []
    all_service_ids: List[str] = []
    all_finding_ids: List[str] = []

    # Process port scanners first (they produce port nodes needed by other modules)
    for mod in ("nmap_scanner", "port_scanner"):
        sr = latest.get(mod)
        if sr and sr.data:
            port_ids, _ = _process_port_scanner(target_node_id, sr.data, nodes, edges, node_ids)
            all_port_ids.extend(p for p in port_ids if p not in all_port_ids)

    # Web analyzer (services + CVEs)
    sr = latest.get("web_analyzer")
    if sr and sr.data:
        svc_ids, fnd_ids = _process_web_analyzer(
            target_node_id, sr.data, nodes, edges, node_ids, all_port_ids
        )
        all_service_ids.extend(svc_ids)
        all_finding_ids.extend(fnd_ids)

    # Nuclei scanner
    sr = latest.get("nuclei_scanner")
    if sr and sr.data:
        fnd_ids = _process_nuclei_scanner(sr.data, nodes, edges, node_ids, all_service_ids)
        all_finding_ids.extend(fnd_ids)

    # SSL scanner
    sr = latest.get("ssl_scanner")
    if sr and sr.data:
        fnd_ids = _process_ssl_scanner(target_node_id, sr.data, nodes, edges, node_ids)
        all_finding_ids.extend(fnd_ids)

    # Generic finding extraction for all remaining modules
    generic_finding_modules = {
        "dns_scanner", "email_security", "http_headers", "axfr_scanner",
        "security_txt", "cors_scanner", "cookie_scanner", "banner_grabber",
        "cloud_scanner", "typosquat_scanner", "crawler",
    }
    for mod_name in generic_finding_modules:
        sr = latest.get(mod_name)
        if sr and sr.data:
            fnd_ids = _build_finding_nodes(
                mod_name, sr.data, all_service_ids, nodes, edges, node_ids
            )
            all_finding_ids.extend(fnd_ids)

    # Chain high-severity findings
    _chain_critical_findings(all_finding_ids, nodes, edges)

    # --- Summary ---
    max_risk = max((n["risk"] for n in nodes), default=0)
    critical_nodes = [n for n in nodes if n["risk"] >= 8]

    # Critical paths: chains of edges leading to critical findings
    critical_finding_ids = {n["id"] for n in critical_nodes if n["type"] == "finding"}
    critical_path_count = len(critical_finding_ids)

    summary = {
        "total_nodes": len(nodes),
        "critical_paths": critical_path_count,
        "max_risk_score": max_risk,
        "node_type_counts": {
            "target": sum(1 for n in nodes if n["type"] == "target"),
            "port": sum(1 for n in nodes if n["type"] == "port"),
            "service": sum(1 for n in nodes if n["type"] == "service"),
            "finding": sum(1 for n in nodes if n["type"] == "finding"),
        },
    }

    return {"nodes": nodes, "edges": edges, "summary": summary}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/attack-path", response_class=HTMLResponse)
async def view_attack_path(
    request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_user_html),
):
    """Render the Attack Path Visualizer page."""
    # Role check: admin, tenant_admin, scanner
    if user.role not in ("admin", "tenant_admin", "scanner"):
        from fastapi import HTTPException, status
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    # Tenant-scoped targets for the dropdown
    if user.role == "admin" and user.tenant_id is None:
        stmt = select(Target).where(Target.is_archived == False).order_by(Target.domain)
    else:
        stmt = select(Target).where(
            Target.tenant_id == user.tenant_id,
            Target.is_archived == False,
        ).order_by(Target.domain)

    targets = session.exec(stmt).all()

    return templates.TemplateResponse("attack_path.html", {
        "request": request,
        "user": user,
        "targets": targets,
    })


@router.get("/api/attack-path/{target_id}")
async def get_attack_path_data(
    target_id: int,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user),
) -> JSONResponse:
    """Return JSON graph data for the given target."""
    # Role check
    if user.role not in ("admin", "tenant_admin", "scanner", "auditor"):
        raise HTTPException(status_code=403, detail="Access denied")

    # Load target with tenant isolation
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    # Tenant isolation: non-admin users can only see their own tenant's targets
    if user.role != "admin" or user.tenant_id is not None:
        if target.tenant_id != user.tenant_id:
            raise HTTPException(status_code=404, detail="Target not found")

    # Load all scan results for this target, ordered desc so dedup keeps latest
    stmt = (
        select(ScanResult)
        .where(ScanResult.target_id == target_id)
        .order_by(ScanResult.scanned_at.desc())
    )
    scan_results = session.exec(stmt).all()

    graph = build_attack_graph(target, list(scan_results))
    return JSONResponse(content=graph)

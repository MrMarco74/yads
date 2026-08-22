"""
Attack Path Visualizer (#45)

Builds a graph of potential attack chains for a given target by aggregating
data from all available scan results. Nodes represent assets, services, ports,
and findings. Edges represent exploitable relationships between them.
"""
import re
from collections import defaultdict
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


_RECON_MODULES = {"dns_scanner", "axfr_scanner", "banner_grabber", "security_txt", "crawler", "typosquat_scanner"}
_INITIAL_ACCESS_MODULES = {"ssl_scanner", "cloud_scanner", "email_security"}
_CRED_MODULES = {"cookie_scanner"}

# MITRE Enterprise tactic ID -> this graph's 5 coarse phase buckets (#51).
# The graph/frontend only understand these 5 phases; mapping real TAxxxx IDs
# onto them keeps _att_phase_for_finding's output format unchanged while
# replacing the guesswork underneath with yads.core.mitre_mapping's real
# module+issue -> technique lookup (Welle 0/5).
_TACTIC_TO_PHASE = {
    "TA0043": "recon", "TA0042": "recon", "TA0007": "recon",
    "TA0001": "initial_access",
    "TA0002": "execution", "TA0003": "execution", "TA0005": "execution",
    "TA0006": "credential_access",
    "TA0004": "impact", "TA0009": "impact", "TA0011": "impact", "TA0040": "impact",
}

# Kill-chain order for real exploit-chaining (#53): a finding in an earlier
# tactic can plausibly "enable" one in a later tactic, never the reverse.
_TACTIC_ORDER = ["TA0043", "TA0042", "TA0001", "TA0002", "TA0003", "TA0004",
                  "TA0005", "TA0006", "TA0007", "TA0009", "TA0011", "TA0040"]


def _att_phase_for_finding(module_name: str, severity: str, issue: str = "") -> str:
    from yads.core.mitre_mapping import get_mitre_mapping
    mitre = get_mitre_mapping(module_name, issue)
    if mitre:
        return _TACTIC_TO_PHASE.get(mitre["tactic_id"], "execution")
    if module_name in _RECON_MODULES:
        return "recon"
    if module_name in _INITIAL_ACCESS_MODULES:
        return "initial_access"
    if module_name in _CRED_MODULES:
        return "credential_access"
    if severity in ("critical", "high"):
        return "impact"
    return "execution"


_IP_RE = re.compile(r'\b(\d{1,3}\.){3}\d{1,3}\b')

def _extract_public_ips(data: Dict) -> set:
    ips = set()
    for m in _IP_RE.finditer(str(data)):
        ip = m.group()
        if not (ip.startswith("10.") or ip.startswith("192.168.")
                or ip.startswith("127.") or ip.startswith("172.")):
            ips.add(ip)
    return ips


def _is_subdomain(child: str, parent: str) -> bool:
    return child != parent and child.endswith("." + parent)


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

            is_ep = port_num in (21, 22, 23, 25, 80, 443, 8080, 8443, 3389, 5900,
                                  1433, 3306, 5432, 6379, 27017)
            nodes.append({
                "id": nid,
                "label": f":{port_num}" + (f" ({service_name})" if service_name else ""),
                "type": "port",
                "risk": risk,
                "att_phase": "initial_access",
                "is_entry_point": is_ep,
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
                       "att_phase": "initial_access", "is_entry_point": True,
                       "metadata": {"port": 80, "service": "http", "banner": ""}})
        edges.append({"source": target_node_id, "target": nid, "label": "exposes"})
        port_node_ids.append(nid)

    if data.get("https", {}).get("open") and "port_443" not in node_ids:
        nid = "port_443"
        node_ids.add(nid)
        nodes.append({"id": nid, "label": ":443 (https)", "type": "port", "risk": 2,
                       "att_phase": "initial_access", "is_entry_point": True,
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
                "att_phase": "execution",
                "is_entry_point": False,
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
            from yads.core.mitre_mapping import get_mitre_mapping
            mitre = get_mitre_mapping(module_name, issue)
            phase = _TACTIC_TO_PHASE.get(mitre["tactic_id"], "execution") if mitre else _att_phase_for_finding(module_name, severity)
            is_ep = (module_name == "cloud_scanner" and "public" in issue.lower())
            nodes.append({
                "id": nid,
                "label": issue[:60],
                "type": "finding",
                "risk": _risk(severity),
                "att_phase": phase,
                "is_entry_point": is_ep,
                "mitre_tactic_id": mitre["tactic_id"] if mitre else None,
                "mitre_technique_id": mitre["technique_id"] if mitre else None,
                "mitre_technique_name": mitre["technique_name"] if mitre else None,
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
    Link high+ findings that plausibly enable each other (#53).

    Previously: every high+ finding was linked to the next in list order
    ("co-exist implies a chain") — a critical SSL finding and an unrelated
    critical subdomain-takeover finding would show as a fabricated 2-step
    attack chain purely because both happened to be in the list.

    Now: only link finding A -> finding B when A's MITRE tactic precedes B's
    in the kill-chain (_TACTIC_ORDER) — a real "this enables that" causal
    ordering (e.g. TA0001 Initial Access -> TA0004 Privilege Escalation is
    plausible; TA0004 -> TA0001 is not). Findings with no resolved MITRE
    tactic (mapping not yet covering that module) are not chained at all,
    rather than guessed — no chain is more honest than a fabricated one.
    """
    node_by_id = {n["id"]: n for n in nodes}
    high_plus = [
        nid for nid in finding_node_ids
        if nid in node_by_id and node_by_id[nid]["risk"] >= 8 and node_by_id[nid].get("mitre_tactic_id")
    ]
    # Sort by kill-chain rank first — otherwise an earlier-tactic finding
    # that merely appears later in `finding_node_ids` (module scan order,
    # not causal order) would never get to point forward to later-tactic
    # findings, since the pairwise scan below only looks ahead in the list.
    def _rank(nid: str) -> int:
        try:
            return _TACTIC_ORDER.index(node_by_id[nid]["mitre_tactic_id"])
        except ValueError:
            return 99
    high_plus.sort(key=_rank)

    for i, source_id in enumerate(high_plus):
        source_tactic = node_by_id[source_id]["mitre_tactic_id"]
        try:
            source_rank = _TACTIC_ORDER.index(source_tactic)
        except ValueError:
            continue
        for target_id in high_plus[i + 1:]:
            target_tactic = node_by_id[target_id]["mitre_tactic_id"]
            try:
                target_rank = _TACTIC_ORDER.index(target_tactic)
            except ValueError:
                continue
            if target_rank > source_rank:
                technique = node_by_id[source_id].get("mitre_technique_name", "")
                edges.append({
                    "source": source_id,
                    "target": target_id,
                    "label": f"enables ({technique})" if technique else "enables",
                })
                break  # one plausible next step per source is enough to avoid a dense fan-out


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
            from yads.core.mitre_mapping import get_mitre_mapping
            mitre = get_mitre_mapping("web_analyzer", cve_id)
            nodes.append({
                "id": nid,
                "label": cve_id,
                "type": "finding",
                "risk": _risk(severity),
                "att_phase": _TACTIC_TO_PHASE.get(mitre["tactic_id"], "execution") if mitre else _att_phase_for_finding("web_analyzer", severity),
                "is_entry_point": False,
                "mitre_tactic_id": mitre["tactic_id"] if mitre else None,
                "mitre_technique_id": mitre["technique_id"] if mitre else None,
                "mitre_technique_name": mitre["technique_name"] if mitre else None,
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
            from yads.core.mitre_mapping import get_mitre_mapping
            mitre = get_mitre_mapping("nuclei_scanner", name)
            nodes.append({
                "id": nid,
                "label": name[:60],
                "type": "finding",
                "risk": _risk(severity),
                "att_phase": _TACTIC_TO_PHASE.get(mitre["tactic_id"], "execution") if mitre else _att_phase_for_finding("nuclei_scanner", severity),
                "is_entry_point": False,
                "mitre_tactic_id": mitre["tactic_id"] if mitre else None,
                "mitre_technique_id": mitre["technique_id"] if mitre else None,
                "mitre_technique_name": mitre["technique_name"] if mitre else None,
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
                    "att_phase": "initial_access",
                    "is_entry_point": False,
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
        "att_phase": "recon",
        "is_entry_point": False,
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
# Tenant-wide graph builder (B: multi-target)
# ---------------------------------------------------------------------------

def build_tenant_attack_graph(
    targets: List[Any],
    scan_results_per_target: Dict[int, List[Any]],
) -> Dict[str, Any]:
    """
    Build a combined attack graph for all tenant targets.
    Adds cross-target pivot edges for shared public IPs and subdomain relationships.
    """
    all_nodes: List[Dict] = []
    all_edges: List[Dict] = []
    target_root_ids: Dict[int, str] = {}
    target_ips: Dict[int, set] = {}

    for target in targets:
        srs = scan_results_per_target.get(target.id, [])
        subgraph = build_attack_graph(target, srs)
        prefix = f"t{target.id}_"

        id_map: Dict[str, str] = {}
        for n in subgraph["nodes"]:
            new_id = prefix + n["id"]
            id_map[n["id"]] = new_id
            n["id"] = new_id
            all_nodes.append(n)

        for e in subgraph["edges"]:
            e["source"] = id_map.get(e["source"], prefix + str(e["source"]))
            e["target"] = id_map.get(e["target"], prefix + str(e["target"]))
            all_edges.append(e)

        target_root_ids[target.id] = prefix + "target_root"

        dns_sr = next((sr for sr in srs if sr.module_name == "dns_scanner"), None)
        if dns_sr and dns_sr.data:
            target_ips[target.id] = _extract_public_ips(dns_sr.data)

    # Cross-target: shared infrastructure (shared public IPs)
    tid_list = list(target_ips.keys())
    seen_pivots: set = set()
    for i, tid_a in enumerate(tid_list):
        for tid_b in tid_list[i + 1:]:
            shared = target_ips[tid_a] & target_ips[tid_b]
            if shared and tid_a in target_root_ids and tid_b in target_root_ids:
                pivot_key = frozenset([tid_a, tid_b])
                if pivot_key not in seen_pivots:
                    seen_pivots.add(pivot_key)
                    all_edges.append({
                        "source": target_root_ids[tid_a],
                        "target": target_root_ids[tid_b],
                        "label": f"shares infra ({list(shared)[0]})",
                        "type": "pivot",
                    })

    # Cross-target: subdomain relationships
    for ta in targets:
        for tb in targets:
            if ta.id != tb.id and _is_subdomain(tb.domain, ta.domain):
                if ta.id in target_root_ids and tb.id in target_root_ids:
                    all_edges.append({
                        "source": target_root_ids[ta.id],
                        "target": target_root_ids[tb.id],
                        "label": "subdomain of",
                        "type": "subdomain",
                    })

    max_risk = max((n["risk"] for n in all_nodes), default=0)
    critical_finding_ids = {n["id"] for n in all_nodes if n["type"] == "finding" and n["risk"] >= 8}

    summary = {
        "total_nodes": len(all_nodes),
        "critical_paths": len(critical_finding_ids),
        "max_risk_score": max_risk,
        "node_type_counts": {
            "target": sum(1 for n in all_nodes if n["type"] == "target"),
            "port": sum(1 for n in all_nodes if n["type"] == "port"),
            "service": sum(1 for n in all_nodes if n["type"] == "service"),
            "finding": sum(1 for n in all_nodes if n["type"] == "finding"),
        },
    }
    return {"nodes": all_nodes, "edges": all_edges, "summary": summary}


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


@router.get("/api/attack-path/tenant")
async def get_tenant_attack_path_data(
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user),
) -> JSONResponse:
    """Return JSON graph data for the entire tenant's attack surface."""
    if user.role not in ("admin", "tenant_admin", "scanner", "auditor"):
        raise HTTPException(status_code=403, detail="Access denied")

    if user.role == "admin" and user.tenant_id is None:
        stmt = select(Target).where(Target.is_archived == False).order_by(Target.domain)
    else:
        stmt = select(Target).where(
            Target.tenant_id == user.tenant_id,
            Target.is_archived == False,
        ).order_by(Target.domain)

    targets = list(session.exec(stmt).all())
    if not targets:
        empty: Dict = {"nodes": [], "edges": [], "summary": {
            "total_nodes": 0, "critical_paths": 0, "max_risk_score": 0,
            "node_type_counts": {"target": 0, "port": 0, "service": 0, "finding": 0},
        }}
        return JSONResponse(content=empty)

    target_ids = [t.id for t in targets]
    sr_stmt = (
        select(ScanResult)
        .where(ScanResult.target_id.in_(target_ids))
        .order_by(ScanResult.scanned_at.desc())
    )
    all_results = list(session.exec(sr_stmt).all())

    scan_results_per_target: Dict[int, List] = defaultdict(list)
    for sr in all_results:
        scan_results_per_target[sr.target_id].append(sr)

    graph = build_tenant_attack_graph(targets, dict(scan_results_per_target))
    return JSONResponse(content=graph)


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

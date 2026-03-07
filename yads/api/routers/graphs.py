import logging
import json
import csv
from io import StringIO, BytesIO
from typing import Optional, List
from fastapi import APIRouter, Depends, Request, Query, HTTPException, Response, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from sqlmodel import Session, select, func, text
from datetime import datetime, timezone

from yads.database import get_session
from yads.auth.deps import get_current_user_html, RoleChecker, get_current_active_user
from yads.models import User, Target, ScanResult, ModuleState
from yads.api.templating import templates

from urllib.parse import urlparse


logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/targets/graph", response_class=HTMLResponse)
async def view_graph_page(request: Request, session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    """
    Renders the Graph View page.
    """
    # Filter by user's tenant and exclude archived targets
    if user.role == "admin" and not user.tenant_id:
        targets = session.exec(select(Target).where(Target.is_archived == False)).all()
    else:
        targets = session.exec(select(Target).where(Target.tenant_id == user.tenant_id, Target.is_archived == False)).all()
        
    return templates.TemplateResponse("graph.html", {"request": request, "targets": targets, "user": user})


@router.get("/api/graph/{target_id}")
async def get_graph_data(target_id: int, session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    """
    Returns nodes and edges for the graph visualization.
    """
    target = session.get(Target, target_id)
    if not target:
        return {"error": "Target not found"}

    # Tenant Check
    if user.role != "admin" or user.tenant_id:
        if target.tenant_id != user.tenant_id:
             return {"error": "Unauthorized access to target"}
             
    nodes = []
    edges = []
    
    # 1. Root Node (The Target)
    nodes.append({
        "id": f"domain_{target.id}", 
        "label": target.domain, 
        "color": "#ff5e5e",
        "shape": "dot",
        "size": 30
    })

    # Fetch latest results
    results = session.exec(select(ScanResult).where(ScanResult.target_id == target_id).order_by(ScanResult.scanned_at.desc())).all()
    
    # DNS Result
    dns = next((r for r in results if r.module_name == 'dns_scanner'), None)
    if dns and dns.data:
        # A Records -> IP Nodes
        for i, ip in enumerate(dns.data.get("a_records", [])):
            ip_node_id = f"ip_{ip}"
            # Check duplicates in list (simple check)
            if not any(n['id'] == ip_node_id for n in nodes):
                nodes.append({"id": ip_node_id, "label": ip, "color": "#2e86de"})
            
            edges.append({"from": f"domain_{target.id}", "to": ip_node_id, "label": "resolves_to", "length": 150})
        
        # Subdomains -> Subdomain Nodes
        for sub in dns.data.get("subdomains", []):
            # sub structure: {subdomain: "...", ips: []}
            s_name = sub.get("subdomain")
            if s_name and s_name != target.domain:
                 sub_id = f"sub_{s_name}"
                 if not any(n['id'] == sub_id for n in nodes):
                     nodes.append({"id": sub_id, "label": s_name, "color": "#ff9f43"})
                 
                 edges.append({"from": f"domain_{target.id}", "to": sub_id, "label": "subdomain", "length": 200})

    # SSL Result
    ssl = next((r for r in results if r.module_name == 'ssl_scanner'), None)
    if ssl and ssl.data and not ssl.data.get("error"):
         issuer = ssl.data.get("issuer", {}).get("commonName")
         if issuer:
             issuer_id = f"issuer_{issuer}"
             if not any(n['id'] == issuer_id for n in nodes):
                 nodes.append({"id": issuer_id, "label": issuer, "color": "#1dd1a1"})
             edges.append({"from": f"domain_{target.id}", "to": issuer_id, "label": "issued_by"})

    # Infra Result
    infra = next((r for r in results if r.module_name == 'infrastructure_scanner'), None)
    if infra and infra.data:
         asn = infra.data.get("asn", {}).get("asn")
         desc = infra.data.get("asn", {}).get("asn_description")
         if asn:
             asn_label = f"{asn}\n{desc}" if desc else asn
             asn_id = f"asn_{asn}"
             if not any(n['id'] == asn_id for n in nodes):
                  nodes.append({"id": asn_id, "label": asn_label, "color": "#a55eea", "shape": "box"})

             # Link to IP or Domain?
             # If we have IPs, usually ASN is linked to IP. But for simplicity, link Domain -> ASN
             edges.append({"from": f"domain_{target.id}", "to": asn_id, "label": "hosted_by"})

    # Deception Detection Results
    deception = next((r for r in results if r.module_name == 'deception_detector'), None)
    if deception and deception.data:
        summary = deception.data.get("summary", {})

        # Add honeypot nodes (amber/orange warning color)
        for hp in deception.data.get("honeypots", []):
            hp_name = hp.get("name", "Unknown")
            hp_type = hp.get("type", "generic")
            hp_conf = hp.get("confidence", 0)
            hp_port = hp.get("port", 0)
            hp_id = f"honeypot_{hp_type}_{hp_port}"

            if not any(n['id'] == hp_id for n in nodes):
                # Color based on confidence: higher = more red/orange
                color = "#f97316" if hp_conf >= 70 else "#fbbf24"  # orange-500 or amber-400
                nodes.append({
                    "id": hp_id,
                    "label": f"🍯 {hp_name}\n({hp_conf}%)",
                    "color": color,
                    "shape": "diamond",
                    "size": 20 + (hp_conf // 10),
                    "title": f"Honeypot: {hp.get('indicator', '')}"
                })
            edges.append({
                "from": f"domain_{target.id}",
                "to": hp_id,
                "label": f"honeypot:{hp_port}",
                "color": {"color": "#f97316", "opacity": 0.7},
                "dashes": True
            })

        # Add sinkhole nodes (red warning color)
        for sh in deception.data.get("sinkholes", []):
            sh_operator = sh.get("sinkhole_operator", "Unknown")
            sh_ip = sh.get("sinkhole_ip", "")
            sh_conf = sh.get("confidence", 0)
            sh_id = f"sinkhole_{sh_ip}" if sh_ip else f"sinkhole_{sh_operator}"

            if not any(n['id'] == sh_id for n in nodes):
                color = "#ef4444" if sh_conf >= 80 else "#f87171"  # red-500 or red-400
                nodes.append({
                    "id": sh_id,
                    "label": f"🕳️ Sinkhole\n{sh_operator}",
                    "color": color,
                    "shape": "triangle",
                    "size": 25,
                    "title": f"Sinkhole: {sh.get('indicator', '')}"
                })
            edges.append({
                "from": f"domain_{target.id}",
                "to": sh_id,
                "label": "sinkholed",
                "color": {"color": "#ef4444", "opacity": 0.8},
                "dashes": True,
                "width": 2
            })

        # Add tarpit nodes (yellow warning color)
        for tp in deception.data.get("tarpits", []):
            tp_type = tp.get("type", "generic")
            tp_port = tp.get("port", 0)
            tp_delay = tp.get("response_delay_ms", 0)
            tp_conf = tp.get("confidence", 0)
            tp_id = f"tarpit_{tp_type}_{tp_port}"

            if not any(n['id'] == tp_id for n in nodes):
                color = "#eab308" if tp_conf >= 60 else "#facc15"  # yellow-500 or yellow-400
                nodes.append({
                    "id": tp_id,
                    "label": f"🐢 Tarpit\n{tp_delay}ms",
                    "color": color,
                    "shape": "square",
                    "size": 18,
                    "title": f"Tarpit: {tp.get('indicator', '')}"
                })
            edges.append({
                "from": f"domain_{target.id}",
                "to": tp_id,
                "label": f"tarpit:{tp_port}",
                "color": {"color": "#eab308", "opacity": 0.6},
                "dashes": [5, 5]
            })

        # Add summary node if significant detections found
        if summary.get("total_detections", 0) > 0:
            risk = summary.get("overall_risk", "none")
            risk_colors = {
                "critical": "#dc2626",
                "high": "#ea580c",
                "medium": "#ca8a04",
                "low": "#65a30d",
                "none": "#6b7280"
            }
            summary_id = f"deception_summary_{target.id}"
            if not any(n['id'] == summary_id for n in nodes):
                nodes.append({
                    "id": summary_id,
                    "label": f"⚠️ Deception\nRisk: {risk.upper()}",
                    "color": risk_colors.get(risk, "#6b7280"),
                    "shape": "star",
                    "size": 30,
                    "title": f"Total detections: {summary.get('total_detections', 0)}, Likelihood: {summary.get('deception_likelihood', 'unknown')}"
                })
            edges.append({
                "from": f"domain_{target.id}",
                "to": summary_id,
                "label": "deception_analysis",
                "color": {"color": risk_colors.get(risk, "#6b7280"), "opacity": 0.5},
                "width": 3
            })

    return {"nodes": nodes, "edges": edges}
async def get_redirect_graph(domain: str = None, session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    """
    Returns graph data (nodes, edges) for the Redirect Spiderweb visualization.
    Optional: ?domain=example.com filter.
    """
    # Filter by user's tenant
    query = select(Target).where(Target.tenant_id == user.tenant_id)
    if domain:
        # Filter by specific domain (exact match on target)
        query = query.where(Target.domain == domain)
        
    targets = session.exec(query).all()
    
    nodes = {} # id -> {id, label, type, value(size)}
    edges = []
    
    # Helper to get/create node
    def get_or_create_node(url, node_type="unknown"):
        # Simplify URL for label (remove protocol)
        if not url: return "unknown"
        label = url.replace("https://", "").replace("http://", "").rstrip('/')
        node_id = label # Use label as ID for simplicity
        
        if node_id not in nodes:
            nodes[node_id] = {
                "id": node_id,
                "label": label,
                "group": node_type, # for vis-network styling
                "value": 1, # size
                "title": url # tooltip
            }
        else:
            # Upgrade type if we find a landing page
            if node_type == "landing" and nodes[node_id]["group"] != "landing":
                 nodes[node_id]["group"] = "landing"
                 
        return node_id

    for t in targets:
        # Get latest Web Scan
        scan = session.exec(select(ScanResult).where(
            ScanResult.target_id == t.id,
            ScanResult.module_name == "web_analyzer"
        ).order_by(ScanResult.scanned_at.desc())).first()
        
        if not scan or not scan.data:
            # Add orphan/unscanned target
            get_or_create_node(t.domain, "source")
            continue
            
        data = scan.data
        chain = data.get("redirect_chain", [])
        
        # Start Node (The Target)
        start_node = get_or_create_node(t.domain, "source")
        
        if not chain:
            pass
        else:
            # Process Chain
            prev_node = start_node
            
            for i, hop_url in enumerate(chain):
                # Determine type
                if i == len(chain) - 1:
                    ntype = "landing" 
                else:
                    ntype = "redirector"
                
                curr_node = get_or_create_node(hop_url, ntype)
                
                # Add Edge
                if prev_node != curr_node:
                    edges.append({
                        "from": prev_node,
                        "to": curr_node,
                        "arrows": "to"
                    })
                
                # Increase size of current node (more incoming links = bigger)
                nodes[curr_node]["value"] += 1
                
                prev_node = curr_node

    return {
        "nodes": list(nodes.values()),
        "edges": edges
    }

@router.get("/api/visualizations/redirects/centrality")
async def get_redirect_centrality(session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    """
    Analyzes the redirect graph to find the most central node (highest degree).
    """
    # 1. Reconstruct Graph (Simplified Logic from get_redirect_graph)
    # We need to build the graph structure in memory to calculate degrees
    targets = session.exec(select(Target).where(Target.tenant_id == user.tenant_id)).all()
    
    # Adjacency List: Node -> {in: 0, out: 0}
    degrees = {}
    
    def touch_node(n):
        if n not in degrees: degrees[n] = {"in": 0, "out": 0}

    for t in targets:
        scan = session.exec(select(ScanResult).where(
            ScanResult.target_id == t.id,
            ScanResult.module_name == "web_analyzer"
        ).order_by(ScanResult.scanned_at.desc())).first()
        
        start_node = t.domain.replace("https://", "").replace("http://", "").rstrip('/')
        touch_node(start_node)
        
        if not scan or not scan.data: continue
        
        chain = scan.data.get("redirect_chain", [])
        if chain:
            prev_node = start_node
            for hop_url in chain:
                curr_node = hop_url.replace("https://", "").replace("http://", "").rstrip('/')
                touch_node(curr_node)
                
                if prev_node != curr_node:
                    degrees[prev_node]["out"] += 1
                    degrees[curr_node]["in"] += 1
                
                prev_node = curr_node

    if not degrees:
        return {"error": "No graph data available."}

    # 2. Find Max Degree (Centrality)
    # Score = In-Degree + Out-Degree (Total Connections)
    sorted_nodes = sorted(
        degrees.items(), 
        key=lambda item: (item[1]["in"] + item[1]["out"]), 
        reverse=True
    )
    
    top_node_id, stats = sorted_nodes[0]
    total_degree = stats["in"] + stats["out"]
    
    if total_degree == 0:
         return {"message": "Graph has no connections."}

    return {
        "node_id": top_node_id,
        "stats": {
            "total_connections": total_degree,
            "inbound": stats["in"],
            "outbound": stats["out"]
        }
    }

@router.get("/api/visualizations/network")
async def get_network_graph(
    target_id: Optional[int] = None, 
    filter_empty: bool = False,
    filter_online: str = "all",
    include_web_links: bool = False,
    max_nodes: int = 500,  # Limit for performance - prevents browser from crashing on large datasets
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user)
):
    """
    Returns graph data (nodes, edges) for the Network Relationship visualization.
    Integrates DNS records and Subdomains.
    max_nodes: Maximum number of target nodes to process (default 500 for performance)
    """
    from sqlmodel import or_, and_, text
    from urllib.parse import urlparse
    
    # Filter by user's tenant and exclude archived targets
    if user.role == "admin" and not user.tenant_id:
        query = select(Target).where(Target.is_archived == False)
    else:
        query = select(Target).where(Target.tenant_id == user.tenant_id, Target.is_archived == False)

    # 1. Online/Offline Filter (using subquery to filter Targets)
    if filter_online != "all":
        online_criteria = or_(
             and_(ScanResult.module_name == 'infrastructure_scanner', text("data->>'ip' IS NOT NULL")),
             and_(ScanResult.module_name == 'web_analyzer', text("(data->>'status_code')::int > 0")),
             and_(ScanResult.module_name == 'port_scanner', text("data->>'is_active' = 'true'"))
        )
        sub_online = select(ScanResult.target_id).where(online_criteria).distinct()

        if filter_online == "online":
            query = query.where(Target.id.in_(sub_online))
        elif filter_online == "offline":
             sub_scanned = select(ScanResult.target_id).distinct()
             query = query.where(Target.id.in_(sub_scanned))
             query = query.where(Target.id.notin_(sub_online))

    if target_id:
        query = query.where(Target.id == target_id)
    
    # Get total count before limiting
    from sqlmodel import func as sqlfunc
    count_query = select(sqlfunc.count()).select_from(query.subquery())
    total_targets = session.exec(count_query).one()
    
    # Apply limit for performance
    query = query.limit(max_nodes)
    targets = session.exec(query).all()
    
    # Track if results were truncated
    truncated = total_targets > max_nodes
    
    nodes = {} # id -> node object (Cytoscape format: {data: {...}})
    edges = [] # list of edge objects (Cytoscape format: {data: {...}})
    
    # Track node risk for Attack Path
    risk_map = {} # node_id -> {is_compromised: bool, risk_score: int, reasons: []}
    
    def get_risk(nid):
        return risk_map.get(nid, {"is_compromised": False, "risk_score": 0, "reasons": []})
    
    # Pre-calculate Risks
    # Iterate scan results to find Critical/High Vulns, Expired Certs, Public Buckets
    target_ids = [t.id for t in targets]
    target_map = {t.id: t.domain for t in targets} # Map target_id to domain string for node ID
    
    if target_ids:
        results = session.exec(select(ScanResult).where(ScanResult.target_id.in_(target_ids))).all()
        
        for res in results:
            if res.target_id not in target_map: continue
            domain_node_id = target_map[res.target_id]
            
            risk_score = 0
            is_compromised = False
            reasons = []
            
            if res.module_name == 'ssl_scanner':
                 if res.data and res.data.get("expired"):
                      risk_score += 10
                      is_compromised = True
                      reasons.append("Expired SSL Certificate")
            elif res.module_name == 'infrastructure_scanner':
                 if res.data:
                     for b in res.data.get("buckets", []):
                          if b.get("status") == "Public":
                               risk_score += 8
                               is_compromised = True
                               reasons.append("Public Cloud Bucket")
            elif res.module_name == 'web_analyzer':
                 if res.data:
                     cves = res.data.get("cves", [])
                     for cve in cves:
                          try:
                               cvss = float(cve.get("cvss", 0))
                               if cvss >= 9.0:
                                    risk_score += 10
                                    is_compromised = True
                                    reasons.append("Critical Vulnerability")
                               elif cvss >= 7.0:
                                    risk_score += 5
                                    if not is_compromised: reasons.append("High Vulnerability")
                          except (ValueError, TypeError) as e:
                               logger.debug(f"Could not parse CVSS for '{cve}': {e}")

            elif res.module_name == 'deception_detector':
                 if res.data:
                     summary = res.data.get("summary", {})
                     overall_risk = summary.get("overall_risk", "none")
                     total_detections = summary.get("total_detections", 0)

                     if total_detections > 0:
                          # Deception indicates potential hostile or monitored infrastructure
                          if overall_risk == "critical":
                               risk_score += 15
                               is_compromised = True
                               reasons.append("Deception Infrastructure (Critical)")
                          elif overall_risk == "high":
                               risk_score += 10
                               is_compromised = True
                               reasons.append("Deception Infrastructure (High)")
                          elif overall_risk == "medium":
                               risk_score += 5
                               reasons.append("Deception Indicators (Medium)")
                          else:
                               risk_score += 2
                               reasons.append("Deception Indicators (Low)")

            if risk_score > 0:
                 if domain_node_id not in risk_map:
                      risk_map[domain_node_id] = {"is_compromised": False, "risk_score": 0, "reasons": []}
                 
                 risk_map[domain_node_id]["risk_score"] += risk_score
                 risk_map[domain_node_id]["is_compromised"] = risk_map[domain_node_id]["is_compromised"] or is_compromised
                 risk_map[domain_node_id]["reasons"].extend(reasons)

    # 2. Build Nodes for Targets
    for t_id in target_ids:
        domain = target_map[t_id]
        t_risk = get_risk(domain)
        
        nodes[domain] = {
            "data": {
                "id": domain,
                "label": domain,
                "type": "domain",
                "risk_score": t_risk["risk_score"], 
                "compromised": t_risk["is_compromised"],
                "risk_reasons": ", ".join(list(set(t_risk["reasons"])))
            }
        }
    
    # 3. Build Edges & Sub-Nodes
    for t_id in target_ids:
        # Fetch Scan Results for edges
        if not target_ids: break # Safety
        
        # Modules to fetch
        modules = ['dns_scanner', 'subdomain_scanner', 'infrastructure_scanner', 'web_analyzer', 'deception_detector']
        if include_web_links:
            modules.append('crawler')

        results = session.exec(select(ScanResult).where(
            ScanResult.target_id == t_id,
            ScanResult.module_name.in_(modules)
        ).order_by(ScanResult.scanned_at.desc())).all()
        
        latest_res = {}
        for r in results:
             if r.module_name not in latest_res: latest_res[r.module_name] = r
             
        source = target_map[t_id]
        source_risk = get_risk(source)
        
        for mod, res in latest_res.items():
            if not res.data: continue
            
            # DNS Edges
            if mod in ['dns_scanner', 'subdomain_scanner']:
                sub_nodes_to_add = set()

                if mod == 'dns_scanner':
                    # Main domain IPs
                     for ip in res.data.get("records", {}).get("A", []):
                        if ip not in nodes:
                            nodes[ip] = { "data": { "id": ip, "label": ip, "type": "ip", "risk_score": 0, "compromised": False } }
                        edges.append({ "data": { "source": source, "target": ip, "label": "resolves_to", "is_risk": source_risk["is_compromised"] } })
                
                if mod == 'subdomain_scanner':
                    for sub_entry in res.data.get("subdomains", []):
                        sub_name = sub_entry.get("subdomain")
                        if sub_name:
                            sub_nodes_to_add.add(sub_name)
                            # Also add IPs for subdomains
                            for ip in sub_entry.get("ips", []):
                                if ip not in nodes:
                                    nodes[ip] = { "data": { "id": ip, "label": ip, "type": "ip", "risk_score": 0, "compromised": False } }
                                edges.append({ "data": { "source": sub_name, "target": ip, "label": "resolves_to", "is_risk": source_risk["is_compromised"] } })

                for sub_id in sub_nodes_to_add:
                    risk = get_risk(sub_id)
                    is_risk_edge = source_risk["is_compromised"]

                    if sub_id not in nodes:
                        nodes[sub_id] = {
                            "data": {
                                "id": sub_id, 
                                "label": sub_id, 
                                "type": "subdomain",
                                "risk_score": risk["risk_score"], 
                                "compromised": risk["is_compromised"],
                                "risk_reasons": ", ".join(list(set(risk["reasons"])))
                            }
                        }
                    
                    edges.append({
                        "data": {
                            "source": source, 
                            "target": sub_id, 
                            "label": "subdomain",
                            "is_risk": is_risk_edge
                        }
                    })

            # Infra (IPs)
            elif mod == 'infrastructure_scanner':
                ip = res.data.get("ip")
                if ip:
                    is_risk_edge = source_risk["is_compromised"]
                    ip_risk = get_risk(ip)

                    if ip not in nodes:
                         nodes[ip] = {
                             "data": {
                                 "id": ip, "label": ip, "type": "ip",
                                 "risk_score": ip_risk["risk_score"], 
                                 "compromised": ip_risk["is_compromised"],
                                 "risk_reasons": ", ".join(list(set(ip_risk["reasons"])))
                            }
                        }
                    edges.append({
                        "data": {
                            "source": source, "target": ip, "label": "resolves_to",
                            "is_risk": is_risk_edge
                        }
                    })
            
            # Crawler (Links)
            elif mod == 'crawler':
                 edges_list = res.data.get("edges", [])
                 for link_edge in edges_list:
                      dst = link_edge.get("target")
                      if not dst: continue
                      try:
                           parsed = urlparse(dst)
                           if parsed.netloc:
                                dst_node = parsed.netloc
                                if dst_node == source: continue

                                # Filter: Only allow links TO scoped domains (Targets or their subdomains)
                                is_scoped = False
                                for t_obj in targets:
                                    t_domain = t_obj.domain
                                    # Check if dst is target or subdomain of target
                                    if dst_node == t_domain or dst_node.endswith("." + t_domain):
                                        is_scoped = True
                                        break
                                
                                if not is_scoped: continue

                                is_risk_edge = source_risk["is_compromised"]
                                dst_risk = get_risk(dst_node)

                                if dst_node not in nodes:
                                     nodes[dst_node] = {
                                         "data": {
                                             "id": dst_node, "label": dst_node, "type": "external",
                                             "risk_score": dst_risk["risk_score"], 
                                             "compromised": dst_risk["is_compromised"],
                                             "risk_reasons": ", ".join(list(set(dst_risk["reasons"])))
                                        }
                                    }
                                
                                edges.append({
                                    "data": {
                                        "source": source, "target": dst_node, "label": "links_to",
                                        "is_risk": is_risk_edge
                                    }
                                })
                      except Exception as e:
                           logger.debug(f"Could not parse URL '{dst}': {e}")

            # Web Analyzer (Redirects)
            elif mod == 'web_analyzer':
                chain = res.data.get("redirect_chain", [])
                if chain:
                    prev_node = source
                    for i, hop_url in enumerate(chain):
                        # Clean URL
                        hop_node = hop_url.replace("https://", "").replace("http://", "").rstrip('/')
                        if hop_node == source: continue # Skip if same as source (e.g. self-redirect)
                        
                        is_risk_edge = source_risk["is_compromised"]
                        hop_risk = get_risk(hop_node)
                        
                        # Node Type
                        ntype = "redirector"
                        if i == len(chain) - 1: ntype = "landing"

                        if hop_node not in nodes:
                             nodes[hop_node] = {
                                 "data": {
                                     "id": hop_node, "label": hop_node, "type": ntype,
                                     "risk_score": hop_risk["risk_score"],
                                     "compromised": hop_risk["is_compromised"],
                                     "risk_reasons": ", ".join(list(set(hop_risk["reasons"])))
                                }
                            }
                        
                        # Add Edge
                        edges.append({
                            "data": {
                                "source": prev_node, "target": hop_node, "label": "redirects_to",
                                "is_risk": is_risk_edge
                            }
                        })
                        
                        prev_node = hop_node

            # Deception Detector (Honeypots, Sinkholes, Tarpits)
            elif mod == 'deception_detector':
                summary = res.data.get("summary", {})
                total_detections = summary.get("total_detections", 0)

                if total_detections > 0:
                    # Add honeypot nodes
                    for hp in res.data.get("honeypots", []):
                        hp_name = hp.get("name", "Unknown")
                        hp_type = hp.get("type", "generic")
                        hp_conf = hp.get("confidence", 0)
                        hp_port = hp.get("port", 0)
                        hp_id = f"honeypot_{source}_{hp_port}"

                        if hp_id not in nodes:
                            nodes[hp_id] = {
                                "data": {
                                    "id": hp_id,
                                    "label": f"Honeypot: {hp_name}",
                                    "type": "honeypot",
                                    "risk_score": hp_conf,
                                    "compromised": hp_conf >= 70,
                                    "risk_reasons": hp.get("indicator", "")
                                }
                            }
                        edges.append({
                            "data": {
                                "source": source,
                                "target": hp_id,
                                "label": f"honeypot:{hp_port}",
                                "is_risk": True
                            }
                        })

                    # Add sinkhole nodes
                    for sh in res.data.get("sinkholes", []):
                        sh_operator = sh.get("sinkhole_operator", "Unknown")
                        sh_ip = sh.get("sinkhole_ip", "")
                        sh_conf = sh.get("confidence", 0)
                        sh_id = f"sinkhole_{source}_{sh_ip}" if sh_ip else f"sinkhole_{source}_{sh_operator}"

                        if sh_id not in nodes:
                            nodes[sh_id] = {
                                "data": {
                                    "id": sh_id,
                                    "label": f"Sinkhole: {sh_operator}",
                                    "type": "sinkhole",
                                    "risk_score": sh_conf,
                                    "compromised": True,
                                    "risk_reasons": sh.get("indicator", "")
                                }
                            }
                        edges.append({
                            "data": {
                                "source": source,
                                "target": sh_id,
                                "label": "sinkholed",
                                "is_risk": True
                            }
                        })

                    # Add tarpit nodes
                    for tp in res.data.get("tarpits", []):
                        tp_type = tp.get("type", "generic")
                        tp_port = tp.get("port", 0)
                        tp_delay = tp.get("response_delay_ms", 0)
                        tp_conf = tp.get("confidence", 0)
                        tp_id = f"tarpit_{source}_{tp_port}"

                        if tp_id not in nodes:
                            nodes[tp_id] = {
                                "data": {
                                    "id": tp_id,
                                    "label": f"Tarpit ({tp_delay}ms)",
                                    "type": "tarpit",
                                    "risk_score": tp_conf,
                                    "compromised": tp_conf >= 60,
                                    "risk_reasons": tp.get("indicator", "")
                                }
                            }
                        edges.append({
                            "data": {
                                "source": source,
                                "target": tp_id,
                                "label": f"tarpit:{tp_port}",
                                "is_risk": tp_conf >= 50
                            }
                        })

    # Filter Empty
    if filter_empty:
        connected_ids = set()
        for e in edges:
            connected_ids.add(e["data"]["source"])
            connected_ids.add(e["data"]["target"])
        nodes = {nid: n for nid, n in nodes.items() if nid in connected_ids}

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "truncated": truncated,
        "total_targets": total_targets,
        "displayed_targets": len(targets)
    }

@router.get("/api/visualizations/network/export")
async def export_network_graph(
    target_id: Optional[int] = None,
    filter_empty: bool = False,
    filter_online: str = "all",
    format: str = "svg", 
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user)
):
    """
    Exports the Network Graph to SVG (Graphviz).
    """
    # Reuse existing logic to get nodes/edges (Cytoscape Format)
    graph_data = await get_network_graph(target_id=target_id, filter_empty=filter_empty, filter_online=filter_online, session=session, user=user)
    nodes = graph_data.get("nodes", [])
    edges = graph_data.get("edges", [])
    
    if format == "svg":
        # Generate DOT source
        dot_lines = ["digraph NetworkGraph {", "  rankdir=LR;", "  node [shape=circle style=filled];"]
        
        # Add Nodes
        for n in nodes:
            data = n.get("data", {})
            # Map Cytoscape types to Graphviz colors/shapes
            color = "#cccccc"
            shape = "ellipse"
            ctype = data.get('type')
            
            if ctype == 'domain': color = "lightblue"; shape="doublecircle"
            elif ctype == 'subdomain': color = "plum"
            elif ctype == 'ip': color = "orange"; shape="box"
            elif ctype == 'external': color = "gray"
            
            # Risk Highlighting
            if data.get('compromised'):
                color = "red"
            
            nid = data.get('id')
            label = data.get('label', '').replace('"', '\\"')
            dot_lines.append(f'  "{nid}" [label="{label}" fillcolor="{color}" shape="{shape}"];')
            
        # Add Edges
        for e in edges:
            data = e.get("data", {})
            src = data.get("source")
            dst = data.get("target")
            
            color = "black"
            if data.get("is_risk"):
                color = "red"
                
            dot_lines.append(f'  "{src}" -> "{dst}" [color="{color}"];')
            
        dot_lines.append("}")
        dot_source = "\n".join(dot_lines)
        
        # Convert to SVG via subprocess
        import asyncio
        try:
            # Async Subprocess
            proc = await asyncio.create_subprocess_exec(
                'dot', '-Tsvg',
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate(input=dot_source.encode())
            
            if proc.returncode != 0:
                print(f"Graphviz Error: {stderr.decode()}")
                return {"error": "Failed to generate graph image"}
                
            return Response(content=stdout, media_type="image/svg+xml")
        except Exception as e:
             logger.error(f"Export Error: {e}")
             return Response(content=f"Export Error: {str(e)}", status_code=500)

    elif format == "excel" or format == "csv":
        # Export for Visio Data Visualizer (Excel)
        import pandas as pd
        from io import BytesIO
        
        # Nodes Sheet
        df_nodes = pd.DataFrame(nodes)
        if not df_nodes.empty:
            # Reorder/Rename if keys exist
            display_cols = ["id", "label", "group"]
            df_nodes = df_nodes[[c for c in display_cols if c in df_nodes.columns]]
            df_nodes.columns = [c.capitalize() for c in df_nodes.columns]
        
        # Edges Sheet
        df_edges = pd.DataFrame(edges)
        if not df_edges.empty:
             display_cols = ["from", "to", "label"]
             df_edges = df_edges[[c for c in display_cols if c in df_edges.columns]]
             df_edges.columns = ["Source", "Target", "Description"]
             
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df_nodes.to_excel(writer, index=False, sheet_name='Nodes')
            df_edges.to_excel(writer, index=False, sheet_name='Edges')
            
        output.seek(0)
        return StreamingResponse(output, media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', headers={
            "Content-Disposition": 'attachment; filename="network_graph_data.xlsx"'
        })
        
    elif format == "graphml":
        # GraphML Export
        # Schema: http://graphml.graphdrawing.org/xmlns
        
        xml_lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<graphml xmlns="http://graphml.graphdrawing.org/xmlns"',
            '    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"',
            '    xsi:schemaLocation="http://graphml.graphdrawing.org/xmlns',
            '     http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd">',
            '  <!-- Node Attributes -->',
            '  <key id="d0" for="node" attr.name="label" attr.type="string"/>',
            '  <key id="d1" for="node" attr.name="type" attr.type="string"/>',
            '  <key id="d2" for="node" attr.name="risk_score" attr.type="int"/>',
            '  <key id="d3" for="node" attr.name="compromised" attr.type="boolean"/>',
            '  <key id="d4" for="node" attr.name="r" attr.type="int"/>',
            '  <key id="d5" for="node" attr.name="g" attr.type="int"/>',
            '  <key id="d6" for="node" attr.name="b" attr.type="int"/>',
             # Add position keys if we had them, but we don't.
             
            '  <!-- Edge Attributes -->',
            '  <key id="e0" for="edge" attr.name="label" attr.type="string"/>',
            '  <key id="e1" for="edge" attr.name="is_risk" attr.type="boolean"/>',
            
            '  <graph id="G" edgedefault="directed">'
        ]
        
        # Color helper
        def hex_to_rgb(hex_code):
             hex_code = hex_code.lstrip('#')
             if len(hex_code) == 6:
                 return tuple(int(hex_code[i:i+2], 16) for i in (0, 2, 4))
             return (128, 128, 128)

        # Style Map
        styles = {
             'domain': '#4f46e5',
             'subdomain': '#0ea5e9',
             'ip': '#10b981',
             'external': '#64748b',
             'landing': '#d946ef',
             'default': '#94a3b8',
             'compromised': '#ef4444'
        }
        
        for n in nodes:
            data = n.get("data", {})
            nid = data.get("id")
            label = data.get("label", "")
            ctype = data.get("type", "default")
            risk = int(data.get("risk_score", 0))
            is_comp = str(data.get("compromised", False)).lower()
            
            # Determine Color
            color_hex = styles.get('compromised') if data.get('compromised') else styles.get(ctype, styles['default'])
            r, g, b = hex_to_rgb(color_hex)
            
            # Helper for XML Escaping
            def xml_escape(val):
                return str(val).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&apos;")

            # XML Escape Node Data
            nid_safe = xml_escape(nid)
            label_safe = xml_escape(label)
            
            xml_lines.append(f'    <node id="{nid_safe}">')
            xml_lines.append(f'      <data key="d0">{label_safe}</data>')
            xml_lines.append(f'      <data key="d1">{ctype}</data>')
            xml_lines.append(f'      <data key="d2">{risk}</data>')
            xml_lines.append(f'      <data key="d3">{is_comp}</data>')
            xml_lines.append(f'      <data key="d4">{r}</data>')
            xml_lines.append(f'      <data key="d5">{g}</data>')
            xml_lines.append(f'      <data key="d6">{b}</data>')
            xml_lines.append('    </node>')
            
        edge_id = 0
        for e in edges:
             data = e.get("data", {})
             src = data.get("source")
             dst = data.get("target")
             lbl = data.get("label", "")
             is_risk = str(data.get("is_risk", False)).lower()
             
             src_safe = xml_escape(src)
             dst_safe = xml_escape(dst)
             lbl_safe = xml_escape(lbl)
             
             xml_lines.append(f'    <edge id="e{edge_id}" source="{src_safe}" target="{dst_safe}">')
             xml_lines.append(f'      <data key="e0">{lbl_safe}</data>')
             xml_lines.append(f'      <data key="e1">{is_risk}</data>')
             xml_lines.append('    </edge>')
             edge_id += 1
             
        xml_lines.append('  </graph>')
        xml_lines.append('</graphml>')
        
        output = "\n".join(xml_lines)
        return Response(content=output, media_type="application/xml", headers={
             "Content-Disposition": 'attachment; filename="yads_network_graph.graphml"'
        })

    return {"error": "Invalid format"}

@router.get("/visualizations/redirect-graph", response_class=HTMLResponse)

async def view_redirect_graph(request: Request, session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    # Fetch all targets for the dropdown
    targets = session.exec(select(Target.domain).order_by(Target.domain)).all()
    return templates.TemplateResponse("redirect_graph.html", {"request": request, "domains": targets, "user": user})

@router.get("/visualizations/network-graph", response_class=HTMLResponse)
async def view_network_graph(request: Request, session: Session = Depends(get_session), user: User = Depends(get_current_active_user)):
    if user.role == "admin" and not user.tenant_id:
        targets = session.exec(select(Target).where(Target.is_archived == False).order_by(Target.domain)).all()
    else:
        targets = session.exec(select(Target).where(Target.tenant_id == user.tenant_id, Target.is_archived == False).order_by(Target.domain)).all()
    return templates.TemplateResponse("network_graph.html", {"request": request, "domains": targets, "user": user})


@router.get("/api/visualizations/network/render-image")
async def render_network_graph_image(
    filter_online: str = "all",
    include_labels: bool = True,
    include_edge_labels: bool = True,
    max_label_length: int = 25,
    session: Session = Depends(get_session),
    user: User = Depends(get_current_active_user)
):
    """
    Server-side rendering of network graph as a static PNG image.
    Handles large graphs (100k+ nodes) that can't be rendered in browser.

    Args:
        filter_online: Filter targets by online status
        include_labels: Whether to include node labels (DNS/Web names)
        include_edge_labels: Whether to include edge labels (connection types)
        max_label_length: Maximum length for labels before truncation
    """
    import networkx as nx
    import numpy as np
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend for server-side rendering
    import matplotlib.pyplot as plt
    from io import BytesIO
    from datetime import datetime

    logger.info(f"[GraphRender] Starting server-side render for tenant {user.tenant_id}")

    # Filter by user's tenant
    if user.role == "admin" and not user.tenant_id:
        query = select(Target)
    else:
        query = select(Target).where(Target.tenant_id == user.tenant_id)

    targets = session.exec(query).all()
    target_ids = [t.id for t in targets]
    target_map = {t.id: t.domain for t in targets}

    logger.info(f"[GraphRender] Processing {len(targets)} targets...")

    # Build NetworkX graph
    G = nx.DiGraph()

    # Add target nodes with full labels
    for t in targets:
        # User requested full names, so we disable truncation
        display_label = t.domain 
        G.add_node(t.domain, type='domain', label=t.domain, display_label=display_label)
    
    # Fetch scan results for edges
    if target_ids:
        results = session.exec(
            select(ScanResult).where(
                ScanResult.target_id.in_(target_ids),
                ScanResult.module_name.in_(['subdomain_scanner', 'infrastructure_scanner', 'web_analyzer'])
            )
        ).all()
        
        # Group by target and get latest per module
        latest_by_target = {}
        for r in results:
            key = (r.target_id, r.module_name)
            if key not in latest_by_target:
                latest_by_target[key] = r
        
        for (t_id, mod), res in latest_by_target.items():
            if not res.data or t_id not in target_map:
                continue
            source = target_map[t_id]

            if mod == 'subdomain_scanner':
                for sub_entry in res.data.get("subdomains", [])[:50]:  # Limit per target
                    sub = sub_entry.get("subdomain")
                    if sub and sub != source:
                        display_label = sub 
                        G.add_node(sub, type='subdomain', label=sub, display_label=display_label)
                        G.add_edge(source, sub, label='subdomain', connection_type='subdomain')

            elif mod == 'infrastructure_scanner':
                ip = res.data.get("ip")
                if ip:
                    G.add_node(ip, type='ip', label=ip, display_label=ip)
                    G.add_edge(source, ip, label='resolves_to', connection_type='resolves_to')

            elif mod == 'web_analyzer':
                chain = res.data.get("redirect_chain", [])
                prev = source
                for hop in chain[:5]:  # Limit chain depth
                    hop_clean = hop.replace("https://", "").replace("http://", "").split("/")[0]
                    if hop_clean and hop_clean != prev:
                        display_label = hop_clean 
                        G.add_node(hop_clean, type='redirect', label=hop_clean, display_label=display_label)
                        G.add_edge(prev, hop_clean, label='redirects_to', connection_type='redirects_to')
                        prev = hop_clean
    
    logger.info(f"[GraphRender] Graph has {G.number_of_nodes()} nodes and {G.number_of_edges()} edges")
    
    # Create figure with appropriate size
    node_count = G.number_of_nodes()
    fig_size = min(100, max(20, node_count / 50))  # Scale figure size with nodes
    fig, ax = plt.subplots(figsize=(fig_size, fig_size), facecolor='#0f172a')
    ax.set_facecolor('#0f172a')
    
    # Calculate layout (spring layout for large graphs)
    logger.info(f"[GraphRender] Computing layout...")
    if node_count > 5000:
        pos = nx.spring_layout(G, k=2/np.sqrt(node_count), iterations=20, seed=42)
    elif node_count > 1000:
        pos = nx.spring_layout(G, k=1/np.sqrt(node_count), iterations=50, seed=42)
    else:
        pos = nx.spring_layout(G, seed=42)
    
    # Color nodes by type
    colors = []
    sizes = []
    for node in G.nodes():
        ntype = G.nodes[node].get('type', 'unknown')
        if ntype == 'domain':
            colors.append('#4f46e5')  # Indigo
            sizes.append(100)
        elif ntype == 'subdomain':
            colors.append('#0ea5e9')  # Cyan
            sizes.append(30)
        elif ntype == 'ip':
            colors.append('#10b981')  # Emerald
            sizes.append(50)
        elif ntype == 'redirect':
            colors.append('#8b5cf6')  # Purple
            sizes.append(40)
        else:
            colors.append('#64748b')  # Slate
            sizes.append(20)
    
    logger.info(f"[GraphRender] Drawing graph...")

    # Draw nodes
    nx.draw_networkx_nodes(G, pos, node_color=colors, node_size=sizes, ax=ax, alpha=0.9)

    # Draw edges
    nx.draw_networkx_edges(G, pos, edge_color='#475569', alpha=0.3, arrows=True, ax=ax, arrowsize=5)

    # Draw node labels (DNS names, Web names)
    if include_labels:
        # Adaptive font size based on node count
        if node_count < 100:
            label_font_size = 8
        elif node_count < 500:
            label_font_size = 6
        elif node_count < 2000:
            label_font_size = 4
        else:
            label_font_size = 3

        # Use display_label for better readability
        display_labels = {node: G.nodes[node].get('display_label', node) for node in G.nodes()}

        nx.draw_networkx_labels(
            G, pos,
            labels=display_labels,
            font_size=label_font_size,
            font_color='#94a3b8',
            font_weight='normal',
            ax=ax,
            verticalalignment='bottom',
            horizontalalignment='center'
        )

    # Draw edge labels (Connection names: subdomain, resolves_to, redirects_to, etc.)
    if include_edge_labels and node_count < 1000:  # Only for manageable graph sizes
        # Adaptive font size for edge labels
        if node_count < 100:
            edge_font_size = 6
        elif node_count < 500:
            edge_font_size = 5
        else:
            edge_font_size = 4

        edge_labels = {(u, v): data.get('label', '') for u, v, data in G.edges(data=True)}

        nx.draw_networkx_edge_labels(
            G, pos,
            edge_labels=edge_labels,
            font_size=edge_font_size,
            font_color='#64748b',
            font_weight='light',
            ax=ax,
            alpha=0.7,
            bbox=dict(boxstyle='round,pad=0.3', facecolor='#0f172a', edgecolor='none', alpha=0.7)
        )

    ax.axis('off')

    # Add watermark/info with legend
    info_text = f"YADS Network Graph | {datetime.now().strftime('%Y-%m-%d %H:%M')} | {node_count} nodes, {G.number_of_edges()} edges"
    fig.text(0.02, 0.02, info_text, fontsize=10, color='#64748b', ha='left')

    # Add legend for node types
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor='#4f46e5', label='Domain'),
        Patch(facecolor='#0ea5e9', label='Subdomain'),
        Patch(facecolor='#10b981', label='IP Address'),
        Patch(facecolor='#8b5cf6', label='Redirect')
    ]
    ax.legend(handles=legend_elements, loc='upper right', framealpha=0.8, facecolor='#1e293b', edgecolor='#475569', labelcolor='#94a3b8')
    
    # Save to buffer
    buf = BytesIO()
    plt.savefig(buf, format='png', dpi=150, bbox_inches='tight', facecolor='#0f172a', edgecolor='none')
    buf.seek(0)
    plt.close(fig)
    
    logger.info(f"[GraphRender] Render complete!")
    
    return StreamingResponse(
        buf,
        media_type="image/png",
        headers={
            "Content-Disposition": f'attachment; filename="network_graph_{datetime.now().strftime("%Y%m%d_%H%M%S")}.png"'
        }
    )

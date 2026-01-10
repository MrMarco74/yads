@app.get("/api/stats/security-risks")
async def get_security_risks(session: Session = Depends(get_session)):
    """
    Aggregates security risks for visualizations:
    - SSL Expiry Timeline
    - Reputation Monitor (Blacklists)
    - Open Buckets
    """
    from datetime import datetime
    
    # helper for filtering latest result of a type
    # (In a real app, this might be a complex window function query, but we loop for simplicity on small datasets)
    
    # Fetch all targets
    targets = session.exec(select(Target)).all()
    
    ssl_timeline = []
    reputation_issues = []
    open_buckets = []
    
    for t in targets:
        # Get latest relevant scans
        # SSL
        ssl_res = session.exec(select(ScanResult).where(
            ScanResult.target_id == t.id,
            ScanResult.module_name == "ssl_scanner"
        ).order_by(ScanResult.scanned_at.desc())).first()
        
        # Infra
        infra_res = session.exec(select(ScanResult).where(
            ScanResult.target_id == t.id,
            ScanResult.module_name == "infrastructure_scanner"
        ).order_by(ScanResult.scanned_at.desc())).first()
        
        # Process SSL
        if ssl_res and ssl_res.data:
            not_after = ssl_res.data.get("notAfter")
            # Format usually: "May 25 12:00:00 2025 GMT" or parsed by our scanner?
            # Our scanner relies on ssl.get_server_certificate or similar.
            # If line 81 of ssl_scanner returning `cert_dict.get('notAfter')`, it is "Mmm dd HH:mm:ss YYYY GMT" usually.
            
            if not_after:
                try:
                    # Parse date string "May 25 12:00:00 2025 GMT"
                    # Python's datetime.strptime can handle this if we match format
                    # Example format from stdlib: 'Oct  5 23:59:59 2025 GMT'
                    try:
                        dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    except:
                        # Sometimes day is single digit with 2 spaces "Oct  5"
                        # Try removing extra spaces or multiple formats
                        # Quickfix: just try generic dateutil if available or robust parse
                         dt = datetime.strptime(not_after.replace("  ", " "), "%b %d %H:%M:%S %Y %Z")
                        
                    days_left = (dt - datetime.utcnow()).days
                    
                    status = "ok"
                    if days_left < 0: status = "expired"
                    elif days_left < 7: status = "critical"
                    elif days_left < 30: status = "warning"
                    
                    ssl_timeline.append({
                        "target": t.domain,
                        "target_id": t.id,
                        "days_left": days_left,
                        "expiry_date": dt.strftime("%Y-%m-%d"),
                        "status": status
                    })
                except Exception as e:
                    pass

        # Process Infra (Reputation + Buckets)
        if infra_res and infra_res.data:
            # Buckets
            buckets = infra_res.data.get("buckets", [])
            for bucket in buckets:
                if bucket.get("status") == "Public":
                    open_buckets.append({
                        "target": t.domain,
                        "target_id": t.id,
                        "url": bucket.get("url"),
                        "code": bucket.get("code")
                    })
            
            # Reputation
            rep = infra_res.data.get("reputation", [])
            if rep:
                ip = infra_res.data.get("ip", "Unknown")
                reputation_issues.append({
                    "target": t.domain,
                    "target_id": t.id,
                    "ip": ip,
                    "issues": rep
                })

    # Sort SSL by urgency
    ssl_timeline.sort(key=lambda x: x["days_left"])
    
    return {
        "ssl_timeline": ssl_timeline,
        "reputation_issues": reputation_issues,
        "open_buckets": open_buckets
    }

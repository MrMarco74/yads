import sqlite3
import json
import os

db_path = "yads.db"  # Check standard location
if not os.path.exists(db_path):
    # Try finding it
    import glob
    dbs = glob.glob("**/*.db", recursive=True)
    if dbs:
        db_path = dbs[0]
        print(f"Using DB: {db_path}")

try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get last target
    cursor.execute("SELECT id, domain, latest_results FROM targets ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    if not row:
        print("No targets found")
        exit()
        
    t_id, domain, results_json = row
    results = json.loads(results_json) if results_json else {}
    
    results["deception_detector"] = {
        "status": "success",
        "data": {
            "honeypots": [
                {
                    "type": "cowrie",
                    "indicator": "SSH-2.0-OpenSSH_7.4",
                    "confidence": 95,
                    "risk_level": "critical",
                    "details": {"reason": "Known Cowrie SSH string"}
                }
            ],
            "sinkholes": [
                {
                    "type": "law_enforcement",
                    "indicator": "sinkhole.shadowserver.org",
                    "confidence": 100,
                    "details": {}
                }
            ],
            "tarpits": [
                {
                    "type": "labrea",
                    "indicator": "Persisting connections with very small window sizes.",
                    "confidence": 80,
                    "details": {}
                }
            ],
            "summary": {
                "deception_likelihood": "high",
                "overall_risk": "critical"
            },
            "recommendations": [
                {
                    "severity": "critical",
                    "title": "Honeypot Detected",
                    "action": "Do not engage further. Infrastructure is likely monitored."
                }
            ]
        },
        "log_content": "Scan completed. Found 1 honeypot, 1 sinkhole, 1 tarpit."
    }
    
    cursor.execute("UPDATE targets SET latest_results = ? WHERE id = ?", (json.dumps(results), t_id))
    conn.commit()
    print(f"Successfully mocked JSON data for target {domain} (ID: {t_id})")
    
except Exception as e:
    print(f"Error: {e}")
finally:
    if 'conn' in locals():
        conn.close()

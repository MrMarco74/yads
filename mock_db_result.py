import json
from yads.core.database import SessionLocal
from yads.core.models import Target

def main():
    db = SessionLocal()
    # Get the last target
    target = db.query(Target).order_by(Target.id.desc()).first()
    if not target:
        print("No targets found")
        return
    
    results = dict(target.latest_results) if target.latest_results else {}
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
    
    target.latest_results = results
    db.commit()
    print(f"Mocked results for target {target.domain}")

if __name__ == "__main__":
    main()

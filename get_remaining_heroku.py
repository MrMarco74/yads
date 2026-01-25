from sqlmodel import Session, select
from yads.database import engine
from yads.models import ScanResult, Target
import json

with Session(engine) as session:
    results = session.exec(select(ScanResult).where(
        ScanResult.module_name.in_(["web_analyzer", "social_media_scanner"])
    )).all()
    
    count = 0
    print("--- REMAINING HEROKU FINDINGS ---")
    for r in results:
        data = r.data
        
        # Web Analyzer
        if "secrets" in data and isinstance(data["secrets"], list):
            for s in data["secrets"]:
                if s.get("type") == "Heroku API Key":
                    t = session.get(Target, r.target_id)
                    domain = t.domain if t else "Unknown"
                    print(f"[WebAnalyzer] Target: {domain} (ID {r.target_id})")
                    print(f"   Value: {s.get('value')}")
                    print(f"   Source: {s.get('source')}")
                    # Show a bit of context if available
                    ctx = s.get('context', '')
                    print(f"   Context: ...{ctx[-100:]}...") 
                    print("-" * 30)
                    count += 1

        # Social Media Scanner
        if "code_exposure" in data and isinstance(data["code_exposure"], list):
            for repo in data["code_exposure"]:
                if "findings" in repo and isinstance(repo["findings"], list):
                    for f in repo["findings"]:
                        if f.get("pattern_name") == "Heroku API Key":
                            print(f"[SocialMedia] Repo: {repo.get('repo_url')}")
                            print(f"   Value: {f.get('redacted_value')}")
                            print(f"   File: {f.get('file_path')}")
                            print("-" * 30)
                            count += 1
    
    print(f"Total Remaining: {count}")

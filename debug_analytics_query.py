from sqlmodel import Session, create_engine, text
from yads.config import settings
from collections import Counter

engine = create_engine(settings.DATABASE_URL)

def debug_query():
    print("--- Debugging Analytics Query ---")
    
    # Exact query from analytics.py
    query = text("""
        SELECT DISTINCT ON (target_id, module_name) 
            target_id, module_name, data, scanned_at 
        FROM scanresult 
        WHERE module_name IN ('infrastructure_scanner', 'web_analyzer', 'tld_scanner', 'cve_scanner')
        ORDER BY target_id, module_name, scanned_at DESC
    """)
    
    with Session(engine) as session:
        rows = session.exec(query).all()
        print(f"Total Rows Returned: {len(rows)}")
        
        tech_counts = Counter()
        web_rows = 0
        
        for row in rows:
            if row.module_name == 'web_analyzer':
                web_rows += 1
                # Check example-client.de ID 23124 (from previous debug)
                if row.target_id == 23124: # Adjust if ID differs in your run, but based on prev output
                     print(f"Found example-client.de (ID {row.target_id}):")
                     print(f" - Scanned At: {row.scanned_at}")
                     print(f" - Tech Stack: {row.data.get('tech_stack')}")
                     
                ts = row.data.get("tech_stack", [])
                tech_counts.update(ts)
                
        print(f"Total Web Analyzer Rows: {web_rows}")
        print(f"Tech Counts: {tech_counts}")

if __name__ == "__main__":
    debug_query()

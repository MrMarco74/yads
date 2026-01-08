
import sys
import os
import uuid
import logging
import dns.resolver
from sqlmodel import select, Session, text

# Add project root to path
sys.path.insert(0, os.getcwd())

from yads.database import SessionLocal, engine
from yads.models import Target, ScanResult

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("wildcard_cleanup")

def detect_wildcard(domain: str) -> set[str]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0
    
    wildcard_ips = set()
    try:
        random_sub = f"{uuid.uuid4().hex[:8]}.{domain}"
        answers = resolver.resolve(random_sub, 'A')
        for r in answers:
            wildcard_ips.add(str(r))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass 
    except Exception as e:
        logger.debug(f"Wildcard check error for {domain}: {e}")
        
    return wildcard_ips

def get_session():
    return SessionLocal()

def run_cleanup():
    logger.info("Starting Wildcard Cleanup (TARGET DELETION MODE)...")
    session = Session(engine)
    
    try:
        # 1. Identify "Wildcard IPs" by checking a known wildcard parent or using a heuristic
        # If we check every single of the 277k targets, it will take forever.
        # Strategy:
        # Group by parent domain?
        # Or just checking "www.webkonferenz.apr23.events.example-client.de" specifically?
        # The user sent: "zzz.www.meinplusexklusivabend.events.example-client.de"
        
        # Let's verify the wildcard IP first using a known bad domain
        # Or blindly trust the wildcard check per target (slow but safe).
        # Optimization: dynamic cache of wildecard IPs per parent domain level.
        
        targets = session.exec(select(Target)).all()
        logger.info(f"Checking {len(targets)} targets...")
        
        deleted_count = 0
        cleaned_results_count = 0
        
        # Cache for wildcard IPs of parent domains
        # Key: "parent.com", Value: {ips...}
        wildcard_cache = {} 
        
        for i, target in enumerate(targets):
            if i % 100 == 0:
                logger.info(f"Processed {i}/{len(targets)} (Deleted: {deleted_count})...")
                
            # Heuristic: If target has NO results or ONLY results that match its own IP...
            # But simpler: If the target ITSELF resolves to a Wildcard IP.
            
            # Resolve target IP
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 1.0
                answers = resolver.resolve(target.domain, 'A')
                target_ips = set([str(r) for r in answers])
            except:
                target_ips = set()
                
            # Check for Wildcard match
            is_wildcard_target = False
            
            # We check the parent domain for wildcard
            # e.g. target: foo.bar.com -> check *.bar.com
            parts = target.domain.split('.')
            if len(parts) > 2:
                parent = ".".join(parts[1:])
                
                if parent not in wildcard_cache:
                    # Check parent wildcard
                    wildcard_cache[parent] = detect_wildcard(parent)
                    
                parent_wildcards = wildcard_cache[parent]
                
                if parent_wildcards and target_ips:
                    # If target IPs overlap with parent wildcard IPs -> Delete Target
                    if not target_ips.isdisjoint(parent_wildcards):
                         is_wildcard_target = True
            
            if is_wildcard_target:
                # DELETE TARGET
                logger.info(f"Deleting Wildcard Target: {target.domain} (IPs: {target_ips})")
                
                # Delete dependencies
                session.exec(text(f"DELETE FROM scanresult WHERE target_id = {target.id}"))
                session.exec(text(f"DELETE FROM modulestate WHERE target_id = {target.id}"))
                session.delete(target)
                deleted_count += 1
                
                if deleted_count % 100 == 0:
                    session.commit()
                continue
            
            # If not deleted, clean its results (existing logic)
            # ... (Existing logic for cleaning subdomains in ScanResult) ...
            # For speed, let's focus on deletion first if that's the main issue.
            # But we should keep the result cleaning too.
            
            # 2. Fetch DNS Scan Results
            scan_results = session.exec(
                select(ScanResult)
                .where(ScanResult.target_id == target.id)
                .where(ScanResult.module_name == "dns_scanner")
            ).all()
            
            if not scan_results:
                continue
                
            updated_res = False
            
            # Local wildcard check for this target (to filter subdomains)
            # We can use the SAME cache logic? 
            # Subdomains of Target would match Target's Wildcard
            
            if target.domain not in wildcard_cache:
                 wildcard_cache[target.domain] = detect_wildcard(target.domain)
                 
            target_wildcards = wildcard_cache[target.domain]
            
            if not target_wildcards:
                continue
                
            for res in scan_results:
                data = res.data
                if not data or "subdomains" not in data:
                    continue
                
                original_count = len(data["subdomains"])
                new_subdomains = []
                
                for sub_entry in data["subdomains"]:
                    ips = sub_entry.get("ips", [])
                    if any(ip in target_wildcards for ip in ips):
                        continue
                    new_subdomains.append(sub_entry)
                
                if len(new_subdomains) < original_count:
                    new_data = dict(data)
                    new_data["subdomains"] = new_subdomains
                    res.data = new_data
                    session.add(res)
                    updated_res = True
            
            if updated_res:
                cleaned_results_count += 1
                
        session.commit()
        logger.info(f"Cleanup Finished. Deleted Targets: {deleted_count}, Cleaned Results: {cleaned_results_count}")
                
    except Exception as e:
        logger.error(f"Cleanup failed: {e}")
    finally:
        session.close()

if __name__ == "__main__":
    run_cleanup()

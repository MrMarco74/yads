import time
import requests
from sqlmodel import Session, select, create_engine, func
from yads.models import ScanResult, Target
from yads.config import settings
import logging

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("repair_geoip")

engine = create_engine(settings.DATABASE_URL)

def repair_geoip():
    logger.info("Starting GeoIP Repair Run...")
    
    with Session(engine) as session:
        # Get all targets
        targets = session.exec(select(Target)).all()
        logger.info(f"Checking {len(targets)} targets for missing GeoIP data...")
        
        fixed_count = 0
        skipped_count = 0
        
        for t in targets:
            # Get latest infrastructure result
            # Use strict ordering to get the one Analytics uses
            scan_res = session.exec(select(ScanResult).where(
                ScanResult.target_id == t.id,
                ScanResult.module_name == "infrastructure_scanner"
            ).order_by(ScanResult.scanned_at.desc())).first()
            
            if not scan_res or not scan_res.data:
                continue
            
            data = scan_res.data
            ip = data.get("ip")
            
            # Check if repair needed: Has IP, but NO GeoIP
            if ip and ip != "0.0.0.0" and not data.get("geoip"):
                logger.info(f"Reparing {t.domain} (IP: {ip})...")
                
                try:
                    # Rate Limit padding (45 req/min = ~1.33s per req)
                    time.sleep(1.5) 
                    
                    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,lat,lon,timezone,isp,org,as"
                    resp = requests.get(url, timeout=5)
                    
                    if resp.status_code == 200:
                        geo_data = resp.json()
                        if geo_data.get("status") == "success":
                            
                            # Update Data
                            # Note: ScanResult.data is JSONB. We need to update the dict and re-assign to trigger dirty flag usually,
                            # or use flag_modified if using SQLAlchemy directly. 
                            # But with SQLModel/Pydantic, re-assigning the dict works best.
                            new_data = dict(data)
                            new_data["geoip"] = {
                                "country_name": geo_data.get("country"),
                                "country_code": geo_data.get("countryCode"),
                                "city": geo_data.get("city"),
                                "lat": geo_data.get("lat"),
                                "lon": geo_data.get("lon"),
                                "isp": geo_data.get("isp"),
                                "org": geo_data.get("org")
                            }
                            
                            # Enhanced Cloud Provider Check (if missing)
                            if not new_data.get("cloud_provider"):
                                isp_org = (geo_data.get("isp") or "") + " " + (geo_data.get("org") or "")
                                isp_org = isp_org.lower()
                                if "amazon" in isp_org or "aws" in isp_org: new_data["cloud_provider"] = "AWS"
                                elif "google" in isp_org: new_data["cloud_provider"] = "GCP"
                                elif "microsoft" in isp_org or "azure" in isp_org: new_data["cloud_provider"] = "Azure"
                                elif "hetzner" in isp_org: new_data["cloud_provider"] = "Hetzner"
                                elif "digitalocean" in isp_org: new_data["cloud_provider"] = "DigitalOcean"
                                elif "cloudflare" in isp_org: new_data["cloud_provider"] = "Cloudflare"

                            scan_res.data = new_data
                            session.add(scan_res)
                            session.commit()
                            session.refresh(scan_res)
                            fixed_count += 1
                            logger.info(f" -> Fixed! Country: {geo_data.get('country')}")
                        else:
                             logger.warning(f" -> API returned failure: {geo_data.get('message')}")
                    else:
                        logger.error(f" -> HTTP Error: {resp.status_code}")
                        
                except Exception as e:
                    logger.error(f" -> Exception during repair: {e}")
            else:
                skipped_count += 1
                
        logger.info(f"Repair Run Completed. Fixed: {fixed_count}, Skipped (OK/NoData): {skipped_count}")

if __name__ == "__main__":
    repair_geoip()

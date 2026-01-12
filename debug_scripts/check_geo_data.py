from sqlmodel import Session, select
from yads.database import engine
from yads.models import ScanResult, Target

def check_geo_data():
    with Session(engine) as session:
        results = session.exec(select(ScanResult).where(ScanResult.module_name == "infrastructure_scanner")).all()
        print(f"Total Infrastructure Scan Results: {len(results)}")
        
        geo_count = 0
        for res in results:
            if res.data and "geoip" in res.data:
                geo_count += 1
                print(f"Found GeoIP for Target {res.target_id}: {res.data['geoip']}")
            else:
                print(f"No GeoIP for Target {res.target_id}")

        print(f"Total Results with GeoIP: {geo_count}")

if __name__ == "__main__":
    check_geo_data()

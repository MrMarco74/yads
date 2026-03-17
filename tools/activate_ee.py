from yads.database import engine
from sqlmodel import Session, select
from yads.models import SystemConfig
from yads.config import settings
import os

LICENSE_KEY = "eyJjdXN0b21lcl9pZCI6ICJjMDBmMWU3ZS1lZjk5LTQ2MzEtODFiNy04YjlkMDc5ZmY5YjUiLCAiZXhwIjogMTgwNTI2NDczMSwgImZlYXR1cmVzIjogWyJyZXBvcnRzIiwgImFwaSIsICJzY2hlZHVsZWRfc2NhbnMiLCAib3NpbnQiLCAid2ViaG9va3MiLCAidGVuYW50cyIsICJhbmFseXRpY3MiLCAic3VwcG9ydF9tZXNzYWdpbmciXSwgImlhdCI6IDE3NzM3Mjg3MzEsICJtYXhfdGFyZ2V0cyI6IDUwMDAsICJyZXBvcnRfc2lnbmluZ19rZXkiOiAiTUxTbFFVZlBHZWpwQ3hrME9Kc2M2OE1oc0JiU2NjTWFVajA1S1pkVlQwTT0iLCAic3ViIjogIlRlc3QifQ.OrLWqtJo910CTHrS4HZO9MZ_XjQmbGPZ4F8GbkiJddVNAxMHcM1xhB8u0EMO7mvKPEfOarlJUGVDNIRDe_OHBQ"

def set_conf(session, key, value):
    conf = session.get(SystemConfig, key)
    if conf:
        conf.value = value
    else:
        conf = SystemConfig(key=key, value=value)
    session.add(conf)

with Session(engine) as session:
    # 1. Deactivate CE
    print("[*] Deactivating Community Edition...")
    set_conf(session, "CE_EDITION", "none")
    set_conf(session, "CE_ACTIVATED_AT", "")
    
    # 2. Inject EE License
    print("[*] Injecting Enterprise License Key...")
    set_conf(session, "license_key", LICENSE_KEY)
    
    session.commit()
    print("[+] Database updated. Restart API/Worker to apply changes.")

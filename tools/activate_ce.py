from yads.database import engine
from sqlmodel import Session
from yads.core.community_edition import activate

with Session(engine) as session:
    if activate(session):
        print("[+] Community Edition activated.")
    else:
        print("[!] Community Edition already active or could not be activated.")

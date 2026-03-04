from rq import Queue
from redis import Redis
from yads.worker import process_target

q = Queue('yads_scans', connection=Redis())
# Get the first target from the DB to scan
from yads.core.database import SessionLocal
from yads.core.models import Target
db = SessionLocal()
t = db.query(Target).first()
if t:
    print(f"Queueing scan for {t.domain}")
    q.enqueue(process_target, t.id, t.domain, ["deception_detector"], {})
else:
    print("No targets found in DB to scan.")

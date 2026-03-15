import os
import sys

# Ensure /app is in path so we can import yads
sys.path.append('/app')

import subprocess
from sqlmodel import Session, create_engine, select
from yads.models import SystemConfig
from yads.config import settings

def main():
    print("[Startup] Initializing Worker Configuration...")
    
    # 1. Connect to Database
    try:
        engine = create_engine(settings.DATABASE_URL)
        concurrency = 8  # Default safe value

        # Env var takes priority over DB setting (useful for docker-compose overrides)
        env_val = os.getenv("WORKER_CONCURRENCY")
        if env_val:
            try:
                v = int(env_val)
                concurrency = v if v > 0 else concurrency
                print(f"[Startup] WORKER_CONCURRENCY from env: {concurrency}")
                env_val = str(v) if v > 0 else None
            except ValueError:
                print(f"[Startup] Malformed WORKER_CONCURRENCY env ({env_val}), checking DB.")
                env_val = None

        if not env_val:
            with Session(engine) as session:
                conf = session.exec(select(SystemConfig).where(SystemConfig.key == "WORKER_CONCURRENCY")).first()
                if conf:
                    try:
                        val = int(conf.value)
                        if val > 0:
                            concurrency = val
                            print(f"[Startup] Found WORKER_CONCURRENCY in DB: {concurrency}")
                        else:
                            print(f"[Startup] Invalid WORKER_CONCURRENCY in DB ({conf.value}), using default.")
                    except ValueError:
                        print(f"[Startup] Malformed WORKER_CONCURRENCY in DB ({conf.value}), using default.")
                else:
                    print(f"[Startup] No WORKER_CONCURRENCY set in DB, using default ({concurrency}).")
    except Exception as e:
        print(f"[Startup] Failed to read settings from DB: {e}. Using default concurrency (8).")
        concurrency = 8

    # 2. Determine which queues to consume
    # Default: celery (standard scans) + discovery (recursive discovery sessions)
    # Override via WORKER_QUEUES env var, e.g. WORKER_QUEUES=celery to disable discovery
    queues = os.getenv("WORKER_QUEUES", "celery,discovery")
    print(f"[Startup] Worker queues: {queues}")

    # 3. Construct Command
    cmd = [
        "celery",
        "-A", "yads.worker",
        "worker",
        "--loglevel=info",
        "--autoscale", f"{concurrency},{concurrency}",
        "-Q", queues,
    ]
    
    print(f"[Startup] Executing: {' '.join(cmd)}")
    
    # 3. Start Scheduler (Background Thread)
    try:
        from yads.core.scheduler import run_scheduler_loop
        from yads.worker import celery_app
        import threading
        
        print("[Startup] Starting Scheduler Thread...")
        t = threading.Thread(target=run_scheduler_loop, args=(celery_app,), daemon=True)
        t.start()
    except Exception as e:
        print(f"[Startup] Failed to start Scheduler: {e}")

    # 4. Execute Celery (Subprocess)
    # We use subprocess.run so the script stays alive for the scheduler thread
    print(f"[Startup] Executing: {' '.join(cmd)}")
    sys.stdout.flush()
    try:
        subprocess.run(cmd, check=True)
    except KeyboardInterrupt:
        print("[Startup] Worker stopping...")

if __name__ == "__main__":
    main()

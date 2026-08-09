import os
import sys
import multiprocessing

# Ensure /app is in path so we can import yads
sys.path.append('/app')

import subprocess
from sqlmodel import Session, create_engine, select
from yads.models import SystemConfig
from yads.config import settings

def _cpu_default() -> int:
    """Conservative default: half of available CPUs.
    Scanners (Playwright, Nuclei, Nmap) are CPU+memory heavy, so running
    cpu_count() parallel scans causes 100% load. Half is a safe starting point.
    Can be overridden via WORKER_CONCURRENCY env var or Settings UI.
    """
    return max(1, multiprocessing.cpu_count() // 2)

def main():
    print("[Startup] Initializing Worker Configuration...")

    # 1. Connect to Database
    try:
        engine = create_engine(settings.DATABASE_URL)
        concurrency = _cpu_default()

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
                            print(f"[Startup] Invalid WORKER_CONCURRENCY in DB ({conf.value}), using cpu_count.")
                    except ValueError:
                        print(f"[Startup] Malformed WORKER_CONCURRENCY in DB ({conf.value}), using cpu_count.")
                else:
                    # No DB entry — write detected value so UI shows it correctly
                    print(f"[Startup] No WORKER_CONCURRENCY in DB — auto-detected {concurrency} (cpu_count). Writing to DB.")
                    try:
                        session.add(SystemConfig(key="WORKER_CONCURRENCY", value=str(concurrency)))
                        session.commit()
                    except Exception as e:
                        print(f"[Startup] Could not write WORKER_CONCURRENCY to DB: {e}")
    except Exception as e:
        print(f"[Startup] Failed to read settings from DB: {e}. Using cpu_count ({_cpu_default()}).")
        concurrency = _cpu_default()

    # 2. Determine which queues to consume
    # Default: celery (standard scans) + discovery (recursive discovery
    # sessions) + utility (admin tool checks/updates that must keep working
    # even while the scan queue is paused -- see worker_core.py).
    # Override via WORKER_QUEUES env var, e.g. WORKER_QUEUES=celery to
    # disable discovery/utility.
    queues = os.getenv("WORKER_QUEUES", "celery,discovery,utility")
    print(f"[Startup] Worker queues: {queues}")

    # 3. Construct Command
    # WORKER_NAME sets a friendly Celery node name (shown in queue view)
    # Falls back to system hostname if not set
    worker_name = os.getenv("WORKER_NAME", "")
    node_name = f"{worker_name}@%h" if worker_name else "celery@%h"

    cmd = [
        "celery",
        "-A", "yads.worker",
        "worker",
        "--loglevel=info",
        "--autoscale", f"{concurrency},{concurrency}",
        "-Q", queues,
        "-n", node_name,
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

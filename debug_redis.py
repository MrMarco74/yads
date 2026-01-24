import os
import redis
import sys

# Mock settings if needed, or just use hardcoded defaults matching docker-compose
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
# If running locally (not in docker), maybe localhost?
# The user's env is linux. If they run this script from terminal, they might not have access to 'redis' hostname unless in /etc/hosts.
# The previous prompt said "http://localhost:8000". So maybe "localhost"?
if "redis" in REDIS_URL and "localhost" not in REDIS_URL:
     print(f"Warning: REDIS_URL is {REDIS_URL}. If running outside Docker, this might fail.")
     # Fallback for local testing if not in container
     # REDIS_URL = "redis://localhost:6379/0" 

try:
    print(f"Connecting to {REDIS_URL}...")
    r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    r.ping()
    print("Redis PING successful.")
    
    q_len = r.llen("celery")
    print(f"Queue 'celery' length: {q_len}")
    
    keys = r.keys("*")
    print(f"All keys: {keys}")
    
except Exception as e:
    print(f"Redis Connection Error: {e}")
    sys.exit(1)

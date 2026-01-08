
import redis
import os

# Connect to Redis (assuming localhost for this script if running outside docker, but inside docker it needs 'redis')
# Since I am running this from the agent environment (host), I need to know the redis port.
# Looking at docker-compose, redis is usually exposed or I can use docker exec.
# I'll try to run this inside the yads-api container.

r = redis.from_url(os.getenv("REDIS_URL", "redis://redis:6379/0"))

print(f"Queue Length (celery): {r.llen('celery')}")
print(f"Queue Items: {r.lrange('celery', 0, 5)}")

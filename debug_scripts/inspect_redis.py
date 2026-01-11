import redis
import json
import base64

r = redis.from_url("redis://redis:6379/0", decode_responses=True)
items = r.lrange("celery", 0, 0)

if items:
    print("RAW ITEM:")
    print(items[0])
    
    try:
        data = json.loads(items[0])
        print("\nDECODED JSON:")
        print(json.dumps(data, indent=2))
        
        if 'body' in data:
            body = data['body']
            print("\nBODY (Raw):", body)
            try:
                # Celery body is often base64 encoded if using serialization
                # But typically it's just a stringified list for json serializer
                body_json = json.loads(base64.b64decode(body).decode('utf-8'))
                print("\nBODY (B64 Decoded):", body_json)
            except:
                print("Body is not base64 or failed to decode.")
                
            try:
                 # Try plain json load
                body_json = json.loads(body)
                print("\nBODY (Plain JSON):", body_json)
            except:
                pass
                
    except Exception as e:
        print("Failed to decode:", e)
else:
    print("Queue is empty. Add a task to inspect.")

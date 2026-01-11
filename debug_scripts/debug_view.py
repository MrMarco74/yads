import requests

try:
    print("Fetching /targets/table...")
    resp = requests.get("http://localhost:8000/targets/table")
    print(f"Status: {resp.status_code}")
    
    content = resp.text
    count = content.count("example.internal")
    print(f"Occurrences of 'example.internal': {count}")
    
    # Also print occurrences of the ID to be sure
    id_count = content.count('value="1169474"')
    print(f"Occurrences of ID 1169474: {id_count}")
    
except Exception as e:
    print(f"Error: {e}")

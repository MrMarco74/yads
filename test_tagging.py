import requests
import sys

def test_tagging():
    base_url = "http://yads-api:8000"
    
    # 1. Get a target ID
    try:
        r = requests.get(f"{base_url}/api/stats/infrastructure") # Using this to get list (since it's not paginated but wait, this returns stats, let's use /targets/table?limit=1 but that returns HTML)
        # Actually /analytics endpoint we modified to pass targets, but that returns HTML.
        # Let's assume we have target 1 or create one if we could, but let's try ID 1.
        target_id = 1449344
        
        print(f"Testing with Target ID: {target_id}")

        # 2. Add Tag
        tag_name = "integration-test-tag"
        print(f"Adding tag '{tag_name}'...")
        r_add = requests.post(f"{base_url}/targets/{target_id}/tags", json={"tag": tag_name})
        if r_add.status_code != 200:
            print(f"Failed to add tag: {r_add.text}")
            return
        
        tags = r_add.json()
        if tag_name in tags:
            print("Tag added successfully.")
        else:
            print("Tag not found in response.")
            return

        # 3. List Tags
        print("Listing all tags...")
        r_list = requests.get(f"{base_url}/api/tags")
        all_tags = r_list.json()
        if tag_name in all_tags:
            print("Tag found in global list.")
        else:
            print(f"Tag not found in global list: {all_tags}")

        # 4. Filter by Tag (Check if parsing works, though result is HTML)
        print("Testing Filter URL...")
        r_filter = requests.get(f"{base_url}/targets/table?filter_tag={tag_name}")
        if r_filter.status_code == 200:
            print("Filter endpoint returned 200 OK.")
        else:
            print(f"Filter endpoint failed: {r_filter.status_code}")

        # 5. Remove Tag
        print(f"Removing tag '{tag_name}'...")
        r_del = requests.delete(f"{base_url}/targets/{target_id}/tags/{tag_name}")
        if r_del.status_code == 200:
             if tag_name not in r_del.json():
                 print("Tag removed successfully.")
             else:
                 print("Tag still present after delete.")
        else:
            print(f"Failed to delete tag: {r_del.text}")

        # 6. Bulk Tagging Test
        print("Testing Bulk Tagging...")
        bulk_tag = "bulk-test-tag"
        # Try adding to target_id and maybe a non-existent one or just the same one
        r_bulk = requests.post(f"{base_url}/targets/bulk/tag", data={
            "target_ids": [target_id],
            "tag": bulk_tag
        }, allow_redirects=False)
        
        if r_bulk.status_code == 303:
            print(f"Bulk tagging returned 303 Redirect (Success). Location: {r_bulk.headers.get('Location')}")
            
            # Verify it's there
            r_check = requests.get(f"{base_url}/api/tags")
            if bulk_tag in r_check.json():
                print("Bulk tag found in global list.")
            else:
                print("Bulk tag NOT found.")
        else:
            print(f"Bulk tagging failed: {r_bulk.status_code} - {r_bulk.text}")

        # 7. Verify 405 on Table POST (Issue Reproduction)
        print("Verifying POST to /targets/table returns 405...")
        r_405 = requests.post(f"{base_url}/targets/table", data={"tag": "fail"})
        if r_405.status_code == 405:
            print("Confirmed: POST /targets/table returns 405 Method Not Allowed (Expected behavior).")
        else:
            print(f"Unexpected status for POST /targets/table: {r_405.status_code}")

        # 8. Verify Bulk Scan Endpoint exists
        print("Verifying POST to /targets/bulk/scan logic...")
        # Just check it doesn't 404/405. It might fail due to empty targets but that's fine.
        r_scan = requests.post(f"{base_url}/targets/bulk/scan", data={"target_ids": [target_id]})
        if r_scan.status_code != 404 and r_scan.status_code != 405:
             print(f"Bulk scan endpoint reachable. Status: {r_scan.status_code}")
        else:
             print(f"Bulk scan endpoint failed: {r_scan.status_code}")

        # 9. Verify Bulk Scan with Options
        print("Verifying Bulk Scan with specific options...")
        # Simulating form submission with multiple checkbox values
        r_opt = requests.post(f"{base_url}/targets/bulk/scan", data=[
            ("target_ids", target_id),
            ("scan_types", "dns_scanner"),
            ("scan_types", "ssl_scanner")
        ], allow_redirects=False)
        
        if r_opt.status_code == 303:
             print(f"Bulk scan with options initiated. Location: {r_opt.headers.get('Location')}")
        else:
             print(f"Bulk scan with options failed: {r_opt.status_code} - {r_opt.text}")

        # 10. Verify Validation Error on Empty Targets (User Report) -> Fixed
        print("Verifying Fix for Empty Targets...")
        # Send post without target_ids
        r_empty = requests.post(f"{base_url}/targets/bulk/tag", data={"tag": "empty-test"}, allow_redirects=False)
        if r_empty.status_code == 303:
             print("Fix Verified: Request without target_ids returns 303 Redirect (Handled Gracefully).")
        else:
             print(f"Fix Failed. Status: {r_empty.status_code} - {r_empty.text}")

    except Exception as e:
        print(f"Test failed with error: {e}")

if __name__ == "__main__":
    test_tagging()

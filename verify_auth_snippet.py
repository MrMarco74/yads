
def test_rbac_logs_queue_denied():
    # Login as viewer
    client.cookies.clear()
    login("viewer", "viewer")
    
    # Try Logs
    response = client.get("/logs")
    assert response.status_code == 403
    
    # Try Logs Stream
    response = client.get("/api/logs/stream")
    assert response.status_code == 403
    
    # Try Queue
    response = client.get("/queue")
    assert response.status_code == 403
    
    # Try Queue Control
    response = client.post("/queue/control", data={"action": "stop"})
    assert response.status_code == 403

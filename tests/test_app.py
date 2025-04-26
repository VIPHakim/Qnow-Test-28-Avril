from fastapi.testclient import TestClient
import pytest
from app import app
import os

client = TestClient(app)

def test_home_page():
    response = client.get("/")
    assert response.status_code == 200
    assert "Orange QoD API Tester" in response.text

def test_create_qos_session():
    test_data = {
        "user_equipment_id": "test-ue-001",
        "qos_profile": "test-profile"
    }
    response = client.post("/qos/request", data=test_data)
    assert response.status_code in [200, 401]  # 401 if no valid token

def test_get_session_status():
    response = client.get("/qos/session/test-session-id")
    assert response.status_code in [200, 401, 404]  # 401 if no valid token, 404 if not found

def test_delete_session():
    response = client.delete("/qos/session/test-session-id")
    assert response.status_code in [200, 401, 404]  # 401 if no valid token, 404 if not found 
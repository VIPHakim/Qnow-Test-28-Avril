from fastapi import FastAPI, HTTPException, Header, Request
from typing import Optional, Dict
import uuid
from datetime import datetime, timedelta
import time

app = FastAPI(title="Mock Orange QoD API")

# In-memory storage for sessions
sessions: Dict[str, dict] = {}

def get_unix_timestamp(seconds_from_now: int = 0) -> int:
    return int(time.time() + seconds_from_now)

@app.post("/qos/request")
async def create_session(request: Request):
    """Mock endpoint for creating a QoS session"""
    try:
        # Get the authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            raise HTTPException(status_code=401, detail="Missing or invalid authorization token")

        # Get the request body
        body = await request.json()

        # Validate required fields
        required_fields = ['device', 'applicationServer', 'qosProfile']
        for field in required_fields:
            if field not in body:
                raise HTTPException(status_code=400, detail=f"Missing required field: {field}")

        # Generate session ID
        session_id = str(uuid.uuid4())
        
        # Get duration or use default
        duration = body.get('duration', 86400)  # Default 24 hours
        
        # Create session info
        now = get_unix_timestamp()
        session_info = {
            "sessionId": session_id,
            "startedAt": now,
            "expiresAt": now + duration,
            "qosStatus": "REQUESTED",
            **body  # Include all request data
        }

        # Store session
        sessions[session_id] = session_info

        # If webhook is configured, we'll simulate status change after 2 seconds
        if body.get('webhook'):
            import asyncio
            asyncio.create_task(simulate_status_change(session_id, body['webhook']))

        return session_info

    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/qos/session/{session_id}")
async def get_session(session_id: str):
    """Mock endpoint for getting session status"""
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    return sessions[session_id]

@app.delete("/qos/session/{session_id}")
async def delete_session(session_id: str):
    """Mock endpoint for deleting a session"""
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session = sessions[session_id]
    
    # Update status to UNAVAILABLE
    session['qosStatus'] = "UNAVAILABLE"
    session['statusInfo'] = "DELETE_REQUESTED"
    
    # If webhook exists, notify about deletion
    if 'webhook' in session:
        import aiohttp
        import json
        webhook = session['webhook']
        event = create_status_changed_event(session_id, "UNAVAILABLE", "DELETE_REQUESTED")
        
        async with aiohttp.ClientSession() as client:
            headers = {}
            if webhook.get('notificationAuthToken'):
                headers['Authorization'] = f"Bearer {webhook['notificationAuthToken']}"
            
            try:
                await client.post(
                    webhook['notificationUrl'],
                    json=event,
                    headers=headers
                )
            except Exception as e:
                print(f"Failed to send webhook notification: {e}")
    
    # Remove session
    del sessions[session_id]
    return {"message": "Session deleted successfully"}

async def simulate_status_change(session_id: str, webhook: dict):
    """Simulate status changes for testing webhooks"""
    import asyncio
    import aiohttp
    
    # Wait 2 seconds before changing status to AVAILABLE
    await asyncio.sleep(2)
    
    if session_id in sessions:
        session = sessions[session_id]
        session['qosStatus'] = "AVAILABLE"
        
        # Send webhook notification
        event = create_status_changed_event(session_id, "AVAILABLE")
        
        async with aiohttp.ClientSession() as client:
            headers = {}
            if webhook.get('notificationAuthToken'):
                headers['Authorization'] = f"Bearer {webhook['notificationAuthToken']}"
            
            try:
                await client.post(
                    webhook['notificationUrl'],
                    json=event,
                    headers=headers
                )
            except Exception as e:
                print(f"Failed to send webhook notification: {e}")

def create_status_changed_event(session_id: str, status: str, status_info: str = None):
    """Create a CloudEvents compliant event"""
    event = {
        "id": str(uuid.uuid4()),
        "source": f"https://mock-api.example.com/qod/v0/sessions/{session_id}",
        "specversion": "1.0",
        "type": "org.camaraproject.qod.v0.qos-status-changed",
        "time": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "data": {
            "sessionId": session_id,
            "qosStatus": status
        }
    }
    
    if status_info:
        event["data"]["statusInfo"] = status_info
    
    return event

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)  # Run on port 8001 to avoid conflict with main app 
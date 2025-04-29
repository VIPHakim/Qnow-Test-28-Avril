from fastapi import FastAPI, HTTPException, Request, status
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
import os
from dotenv import load_dotenv
import aiohttp
from typing import Optional, List
from pydantic import BaseModel, HttpUrl, Field, IPvAnyAddress, constr
from enum import Enum
import uuid
import time
import base64

# Load environment variables
load_dotenv()

API_BASE_URL = "https://api.orange.com/camara/quality-on-demand/orange-lab/v0"

app = FastAPI(title="Orange QoD API Tester")

# Mount static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# OAuth2 Credentials
CLIENT_ID = "f1yQkufLpcgSC0YZHV9tpNBxeSAjFNPd"
CLIENT_SECRET = "UJXn5yFO3GXr7MocZ5zPlfxZC2JpIqg3g0fIlgOPb1g9"
OAUTH_URL = "https://api.orange.com/oauth/v3/token"

# Token cache
global_access_token = None
global_token_expiry = 0

async def get_access_token():
    global global_access_token, global_token_expiry
    # If token is still valid, return it
    if global_access_token and time.time() < global_token_expiry - 60:
        return global_access_token

    # Otherwise, request a new token
    async with aiohttp.ClientSession() as session:
        basic_auth = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
        headers = {
            "Authorization": f"Basic {basic_auth}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json"
        }
        data = {
            "grant_type": "client_credentials"
        }
        async with session.post(OAUTH_URL, headers=headers, data=data) as resp:
            if resp.status != 200:
                error = await resp.text()
                raise HTTPException(status_code=503, detail=f"Failed to get access token: {error}")
            token_data = await resp.json()
            global_access_token = token_data["access_token"]
            global_token_expiry = time.time() + int(token_data["expires_in"])
            return global_access_token

# Pydantic models for request validation
class Port(BaseModel):
    """TCP or UDP port number"""
    value: int = Field(..., ge=0, le=65535)

class PortRange(BaseModel):
    """Port range specification"""
    from_: int = Field(..., ge=0, le=65535, alias="from")
    to: int = Field(..., ge=0, le=65535)

    class Config:
        allow_population_by_field_name = True

class PortsSpec(BaseModel):
    """Port specification including ranges and individual ports"""
    ranges: Optional[List[PortRange]] = Field(None, min_items=1)
    ports: Optional[List[int]] = Field(None, min_items=1)

    class Config:
        schema_extra = {
            "example": {
                "ranges": [{"from": 5010, "to": 5020}],
                "ports": [5060, 5070]
            }
        }

class DeviceIpv4Addr(BaseModel):
    """IPv4 address specification for a device"""
    publicAddress: str = Field(..., example="84.125.93.10")
    privateAddress: Optional[str] = None
    publicPort: Optional[int] = Field(None, ge=0, le=65535)

class Device(BaseModel):
    """Device identification information"""
    phoneNumber: Optional[str] = Field(None, pattern=r'^\+?[0-9]{5,15}$', example="123456789")
    networkAccessIdentifier: Optional[str] = Field(None, example="123456789@domain.com")
    ipv4Address: Optional[DeviceIpv4Addr] = None
    ipv6Address: Optional[str] = Field(None, example="2001:db8:85a3:8d3:1319:8a2e:370:7344")

class ApplicationServer(BaseModel):
    """Application server identification"""
    ipv4Address: Optional[str] = Field(None, example="192.168.0.1/24")
    ipv6Address: Optional[str] = Field(None, example="2001:db8:85a3:8d3:1319:8a2e:370:7344")

class Webhook(BaseModel):
    """Webhook configuration for notifications"""
    notificationUrl: HttpUrl
    notificationAuthToken: Optional[str] = Field(None, min_length=20, max_length=256)

class QoSSessionRequest(BaseModel):
    """Request model for creating a QoS session"""
    duration: int = Field(
        default=86400,
        ge=1,
        le=86400,
        description="Session duration in seconds. Maximum 24 hours."
    )
    device: Device
    applicationServer: ApplicationServer
    devicePorts: Optional[PortsSpec] = None
    applicationServerPorts: Optional[PortsSpec] = None
    qosProfile: str = Field(..., min_length=3, max_length=256, pattern=r'^[a-zA-Z0-9_.-]+$')
    webhook: Optional[Webhook] = None

class QosStatus(str, Enum):
    """QoS session status"""
    REQUESTED = "REQUESTED"
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"

class Severity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"

class Message(BaseModel):
    """Status message"""
    severity: Severity
    description: str

class SessionInfo(QoSSessionRequest):
    """Session information including status"""
    sessionId: uuid.UUID
    startedAt: int
    expiresAt: int
    qosStatus: QosStatus
    messages: Optional[List[Message]] = None

async def make_api_request(method: str, endpoint: str, data: dict = None):
    token = await get_access_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    print(f"Making {method} request to {endpoint}")  # Debug print
    print(f"Headers: {headers}")  # Debug print
    print(f"Data: {data}")  # Debug print

    async with aiohttp.ClientSession() as session:
        url = f"{API_BASE_URL}{endpoint}"
        try:
            if method == "GET":
                async with session.get(url, headers=headers) as response:
                    return await response.json(), response.status
            elif method == "POST":
                async with session.post(url, headers=headers, json=data) as response:
                    if response.status >= 400:
                        error_text = await response.text()
                        print(f"Error response: {error_text}")  # Debug print
                        return {"error": error_text}, response.status
                    return await response.json(), response.status
            elif method == "DELETE":
                async with session.delete(url, headers=headers) as response:
                    return await response.json(), response.status
        except aiohttp.ClientError as e:
            print(f"Client error in make_api_request: {str(e)}")  # Debug print
            raise HTTPException(status_code=500, detail=str(e))
        except Exception as e:
            print(f"Unexpected error in make_api_request: {str(e)}")  # Debug print
            raise HTTPException(status_code=500, detail=str(e))

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Render the home page"""
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "api_token_configured": bool(API_BASE_URL)
        }
    )

@app.post("/qos/request")
async def create_qos_session(request: QoSSessionRequest):
    """Create a new QoS session"""
    try:
        print(f"Received request data: {request.dict()}")  # Debug print
        response, status = await make_api_request("POST", "/qos/request", request.dict(exclude_none=True))
        return {"status": status, "response": response}
    except Exception as e:
        print(f"Error in create_qos_session: {str(e)}")  # Debug print
        import traceback
        traceback.print_exc()  # Print full traceback
        raise HTTPException(
            status_code=500,
            detail={
                "error": str(e),
                "type": type(e).__name__,
                "request_data": request.dict(exclude_none=True)
            }
        )

@app.get("/qos/session/{session_id}")
async def get_session_status(session_id: str):
    """Get status of a QoS session"""
    response, status = await make_api_request("GET", f"/qos/session/{session_id}")
    return {"status": status, "response": response}

@app.delete("/qos/session/{session_id}")
async def delete_session(session_id: str):
    """Delete a QoS session"""
    response, status = await make_api_request("DELETE", f"/qos/session/{session_id}")
    return {"status": status, "response": response}

@app.get("/qos/profiles")
async def get_qos_profiles():
    """
    Get all QoS profiles managed by the Orange QoS server.
    """
    response, status = await make_api_request("GET", "/qos-profiles")
    return {"status": status, "profiles": response}

@app.get("/token/status")
async def token_status():
    try:
        token = await get_access_token()
        return {"status": "granted", "message": "Access token is valid and granted."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host=host, port=port) 
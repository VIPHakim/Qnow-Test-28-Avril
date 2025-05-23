from fastapi import FastAPI, HTTPException, Request, status
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
import os
from dotenv import load_dotenv
import aiohttp
from typing import Optional, List, Dict
from pydantic import BaseModel, HttpUrl, Field, IPvAnyAddress, constr, validator
from enum import Enum
import time
import base64
import json
import re
import hashlib
import logging
import traceback
import uuid
import ipaddress

# Load environment variables
load_dotenv()

API_BASE_URL = os.getenv("API_BASE_URL", "https://api.orange.com/camara/quality-on-demand/orange-lab/v0")

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
        populate_by_name = True

class PortsSpec(BaseModel):
    """Port specification including ranges and individual ports"""
    ranges: Optional[List[PortRange]] = Field(None, min_items=1)
    ports: Optional[List[int]] = Field(None, min_items=1)

    class Config:
        json_schema_extra = {
            "example": {
                "ranges": [{"from": 5010, "to": 5020}],
                "ports": [5060, 5070]
            }
        }

class DeviceIpv4Addr(BaseModel):
    """IPv4 address specification for a device"""
    publicAddress: str = Field(..., example="172.20.120.105", pattern=r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    privateAddress: Optional[str] = Field(None, example="172.20.120.105", pattern=r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')

class Device(BaseModel):
    """Device identification information"""
    ipv4Address: DeviceIpv4Addr = Field(..., description="IPv4 address information")
    ipv6Address: Optional[str] = Field(None, example="2001:db8:85a3:8d3:1319:8a2e:370:7344", description="IPv6 address")

class ApplicationServer(BaseModel):
    """Application server identification"""
    ipv4Address: str = Field(
        ..., 
        example="172.20.120.84",
        pattern=r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    ipv6Address: Optional[str] = Field(None, example="2001:db8:85a3:8d3:1319:8a2e:370:7344", description="IPv6 address of the application server")

    @validator('ipv4Address')
    def validate_ipv4(cls, v):
        if '/' in v:  # Reject CIDR notation
            raise ValueError('CIDR notation is not allowed. Please provide a specific IPv4 address.')
        return v

class Webhook(BaseModel):
    """Webhook configuration for notifications"""
    notificationUrl: HttpUrl
    notificationAuthToken: Optional[str] = Field(None, min_length=20, max_length=256)

class QoSSessionRequest(BaseModel):
    """Request model for creating a QoS session"""
    duration: int = Field(
        default=600,
        ge=1,
        le=86400,
        description="Session duration in seconds. Maximum 24 hours."
    )
    device: Device
    applicationServer: ApplicationServer
    devicePorts: PortsSpec = Field(
        default_factory=lambda: PortsSpec(ports=[50984])
    )
    applicationServerPorts: PortsSpec = Field(
        default_factory=lambda: PortsSpec(ports=[10000])
    )
    qosProfile: str = Field(
        ...,
        description="QoS profile name (e.g., 'low', 'medium', 'high', etc.)"
    )
    webhook: Optional[Webhook] = None

    class Config:
        json_schema_extra = {
            "example": {
                "duration": 600,
                "device": {
                    "ipv4Address": {
                        "publicAddress": "172.20.120.105",
                        "privateAddress": "172.20.120.105"
                    }
                },
                "applicationServer": {
                    "ipv4Address": "172.20.120.84"
                },
                "devicePorts": {
                    "ports": [50984]
                },
                "applicationServerPorts": {
                    "ports": [10000]
                },
                "qosProfile": "low"  # Use a profile name, not UUID
            }
        }

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
    try:
        token = await get_access_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Cache-Control": "no-cache",
            "X-OAPI-Request-Id": str(uuid.uuid4())  # Add request ID for tracking
        }
        print(f"\n=== API Request Details ===")
        print(f"Method: {method}")
        print(f"Endpoint: {endpoint}")
        print(f"Headers: {json.dumps(headers, indent=2)}")
        if data:
            print(f"Request Data: {json.dumps(data, indent=2)}")

        async with aiohttp.ClientSession() as session:
            url = f"{API_BASE_URL}{endpoint}"
            print(f"Full URL: {url}")

            async with session.post(url, headers=headers, json=data) if method == "POST" else \
                     session.get(url, headers=headers) if method == "GET" else \
                     session.delete(url, headers=headers) as response:
                
                print(f"\n=== API Response Details ===")
                print(f"Status Code: {response.status}")
                print(f"Response Headers: {dict(response.headers)}")
                
                response_text = await response.text()
                print(f"Raw Response Text: {response_text}")
                
                try:
                    if response_text:
                        response_json = json.loads(response_text)
                        print(f"Parsed Response JSON: {json.dumps(response_json, indent=2)}")
                        
                        # Check for specific error patterns
                        if response.status >= 400:
                            error_detail = response_json.get('details', '')
                            if 'Error id' in error_detail:
                                print(f"\n=== Error Analysis ===")
                                print(f"Error ID found: {error_detail}")
                                print("Possible issues:")
                                print("1. Token validation")
                                print("2. Request format")
                                print("3. Server-side validation")
                                print("4. Resource availability")
                            return {"error": response_json}, response.status
                        return response_json, response.status
                    return {}, response.status
                except json.JSONDecodeError as je:
                    print(f"JSON Decode Error: {str(je)}")
                    return {"error": response_text}, response.status
                
    except aiohttp.ClientError as e:
        print(f"Client Error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"API Client Error: {str(e)}")
    except Exception as e:
        print(f"Unexpected Error: {str(e)}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Unexpected Error: {str(e)}")

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
        print("\n=== Processing QoS Session Request ===")
        print(f"Input Request: {request.model_dump_json()}")
        print(f"Requested QoS Profile: {request.qosProfile}")

        # Directly use the requested profile ID
        # This assumes the frontend is sending the correct profile ID directly
        profile_id = request.qosProfile
        
        print(f"\nUsing QoS Profile ID: {profile_id}")

        # Format the request EXACTLY as in the Orange example
        formatted_request = {
            "duration": request.duration,
            "device": {
                "ipv4Address": {
                    "publicAddress": request.device.ipv4Address.publicAddress,
                    "privateAddress": request.device.ipv4Address.privateAddress
                }
            },
            "applicationServer": {
                "ipv4Address": request.applicationServer.ipv4Address
            },
            "devicePorts": {
                "ports": [50984]
            },
            "applicationServerPorts": {
                "ports": [10000]
            },
            "qosProfile": str(profile_id)  # Ensure it's a string
        }

        # Only add webhook if provided
        if request.webhook and request.webhook.notificationUrl:
            formatted_request["webhook"] = {
                "notificationUrl": str(request.webhook.notificationUrl)
            }

        print(f"\n=== Formatted Request ===")
        print(json.dumps(formatted_request, indent=2))

        # Make the API request
        response, status = await make_api_request("POST", "/sessions", formatted_request)
        
        print(f"\n=== Final Response ===")
        print(f"Status: {status}")
        print(f"Response: {json.dumps(response, indent=2)}")
        
        return {"status": status, "response": response}
        
    except HTTPException as he:
        print(f"HTTP Exception: {str(he)}")
        raise he
    except Exception as e:
        print(f"Error in create_qos_session: {str(e)}")
        traceback.print_exc()
        error_data = request.model_dump() if hasattr(request, 'model_dump') else request.dict()
        raise HTTPException(
            status_code=500,
            detail={
                "error": str(e),
                "type": type(e).__name__,
                "request_data": error_data
            }
        )

@app.get("/qos/session/{session_id}")
async def get_session_status(session_id: str):
    """Get status of a QoS session"""
    response, status = await make_api_request("GET", f"/sessions/{session_id}")
    return {"status": status, "response": response}

@app.delete("/qos/session/{session_id}")
async def delete_session(session_id: str):
    """Delete a QoS session"""
    response, status = await make_api_request("DELETE", f"/sessions/{session_id}")
    return {"status": status, "response": response}

@app.get("/qos/profiles")
async def get_qos_profiles():
    """Get available QoS profiles from Orange CAMARA QoD API"""
    try:
        print("\n===== FETCHING QOS PROFILES =====")
        print(f"API_BASE_URL: {API_BASE_URL}")
        
        # Get a fresh token
        token = await get_access_token()
        if not token:
            print("ERROR: Failed to obtain token for QoS profiles request")
            return JSONResponse(
                status_code=401,
                content={
                    "code": "UNAUTHENTICATED",
                    "status": 401,
                    "message": "Authorization failed: Failed to obtain authentication token"
                }
            )
        
        print(f"Token obtained successfully: {token[:10]}...")
            
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Cache-Control": "no-cache"
        }
        
        print(f"Request headers: {headers}")
        
        async with aiohttp.ClientSession() as client:
            url = f"{API_BASE_URL}/qos-profiles"
            print(f"Making request to URL: {url}")
            
            try:
                async with client.get(url, headers=headers) as response:
                    print(f"QoS profiles response status: {response.status}")
                    print(f"QoS profiles response headers: {dict(response.headers)}")
                    
                    try:
                        response_text = await response.text()
                        print(f"Raw response text: {response_text}")
                        
                        try:
                            response_data = json.loads(response_text)
                            print(f"Parsed response data type: {type(response_data)}")
                            print(f"QoS profiles response data: {json.dumps(response_data, indent=2)}")
                            
                            if response.status == 200:
                                # Validate and transform response to match Orange API format
                                if isinstance(response_data, list):
                                    print(f"Found {len(response_data)} profiles in array")
                                    profiles = []
                                    for i, profile in enumerate(response_data):
                                        print(f"Processing profile {i}: {profile}")
                                        if isinstance(profile, dict):
                                            profile_data = {
                                                "name": profile.get("name"),
                                                "description": profile.get("description"),
                                                "status": profile.get("status", "ACTIVE"),
                                                "id": profile.get("id")
                                            }
                                            # Only add optional fields if they exist
                                            if "parameters" in profile:
                                                profile_data["parameters"] = profile["parameters"]
                                            profiles.append(profile_data)
                                    
                                    print(f"Returning {len(profiles)} processed profiles")
                                    print(f"Final profiles data: {json.dumps(profiles, indent=2)}")
                                    # Return profiles directly as a list rather than wrapped in an object
                                    return profiles
                                else:
                                    print(f"Error: Response is not a list but {type(response_data)}")
                                    return JSONResponse(
                                        status_code=500,
                                        content={
                                            "code": "INTERNAL",
                                            "status": 500,
                                            "message": "Invalid response format from Orange API"
                                        }
                                    )
                            
                            elif response.status == 401:
                                print("Error 401: Authorization failed")
                                return JSONResponse(
                                    status_code=401,
                                    content={
                                        "code": "UNAUTHENTICATED",
                                        "status": 401,
                                        "message": "Authorization failed"
                                    }
                                )
                            elif response.status == 403:
                                print("Error 403: Permission denied")
                                return JSONResponse(
                                    status_code=403,
                                    content={
                                        "code": "PERMISSION_DENIED",
                                        "status": 403,
                                        "message": "Operation not allowed"
                                    }
                                )
                            else:
                                error_message = response_data.get("message", "Unknown error")
                                print(f"Error {response.status}: {error_message}")
                                return JSONResponse(
                                    status_code=response.status,
                                    content={
                                        "code": "INTERNAL",
                                        "status": response.status,
                                        "message": error_message
                                    }
                                )
                                
                        except json.JSONDecodeError as e:
                            print(f"JSON Decode Error: {str(e)}")
                            print(f"Raw response content: {response_text}")
                            return JSONResponse(
                                status_code=500,
                                content={
                                    "code": "INTERNAL",
                                    "status": 500,
                                    "message": f"Invalid JSON response from Orange API: {str(e)}"
                                }
                            )
                    except Exception as e:
                        print(f"Error reading response: {str(e)}")
                        return JSONResponse(
                            status_code=500,
                            content={
                                "code": "INTERNAL",
                                "status": 500,
                                "message": f"Error reading response: {str(e)}"
                            }
                        )
            except aiohttp.ClientError as e:
                print(f"HTTP request error: {str(e)}")
                return JSONResponse(
                    status_code=500,
                    content={
                        "code": "INTERNAL",
                        "status": 500,
                        "message": f"HTTP request error: {str(e)}"
                    }
                )
                
    except aiohttp.ClientError as e:
        print(f"Network error while fetching QoS profiles: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={
                "code": "INTERNAL",
                "status": 500,
                "message": f"Network error: {str(e)}"
            }
        )
    except Exception as e:
        print(f"Unexpected error in get_qos_profiles: {str(e)}")
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={
                "code": "INTERNAL",
                "status": 500,
                "message": f"Internal server error: {str(e)}"
            }
        )

@app.get("/token/status")
async def token_status():
    try:
        token = await get_access_token()
        return {"status": "granted", "message": "Access token is valid and granted."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/test/qos/profiles")
async def test_qos_profiles():
    """Test endpoint that returns sample QoS profiles"""
    print("Returning sample QoS profiles for testing")
    sample_profiles = [
        {
            "id": "low",
            "name": "Low",
            "description": "Low priority QoS profile",
            "status": "ACTIVE"
        },
        {
            "id": "medium",
            "name": "Medium",
            "description": "Medium priority QoS profile",
            "status": "ACTIVE"
        },
        {
            "id": "high",
            "name": "High",
            "description": "High priority QoS profile",
            "status": "ACTIVE"
        },
        {
            "id": "verylow",
            "name": "Very Low",
            "description": "Very low priority QoS profile",
            "status": "ACTIVE"
        },
        {
            "id": "profile-10m",
            "name": "Profile 10M",
            "description": "10Mbps profile",
            "status": "ACTIVE"
        }
    ]
    return sample_profiles

if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host=host, port=port) 
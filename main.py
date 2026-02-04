import os
from datetime import datetime
from decimal import Decimal
import json
import base64
import hashlib
import hmac
import time
from uuid import uuid4
from typing import Optional

import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
import httpx

load_dotenv()
app = FastAPI()

API_KEY = os.getenv("API_KEY")
AWS_REGION = os.getenv("AWS_REGION")  # optional (boto3 can infer)
DYNAMODB_ENDPOINT_URL = os.getenv("DYNAMODB_ENDPOINT_URL")  # optional (useful for DynamoDB Local)
DYNAMODB_ORDERS_TABLE = os.getenv("DYNAMODB_ORDERS_TABLE", "clover_orders")
DYNAMODB_WEBHOOK_TABLE = os.getenv("DYNAMODB_WEBHOOK_TABLE", "clover_webhook_events")
DYNAMODB_INSTALLS_TABLE = os.getenv("DYNAMODB_INSTALLS_TABLE", "clover_installs")

# Clover OAuth v2 (expiring access tokens + refresh tokens).
# Docs: https://docs.clover.com/dev/docs/oauth-intro
CLOVER_CLIENT_ID = os.getenv("CLOVER_CLIENT_ID")
CLOVER_CLIENT_SECRET = os.getenv("CLOVER_CLIENT_SECRET")
CLOVER_REDIRECT_URI = os.getenv("CLOVER_REDIRECT_URI")  # e.g. https://api.myapp.com/oauth/callback
# "us" (default) or "eu"
CLOVER_REGION = (os.getenv("CLOVER_REGION") or "us").lower()
OAUTH_STATE_SECRET = os.getenv("OAUTH_STATE_SECRET")  # required if you use /oauth/start

if not API_KEY:
    raise RuntimeError("Missing required env var: API_KEY")

# Allow your Vercel frontend (and local dev) to call this API.
# In production, replace '*' with your Vercel domain(s), e.g. "https://my-app.vercel.app"
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

_dynamodb = boto3.resource(
    "dynamodb",
    region_name=AWS_REGION,
    endpoint_url=DYNAMODB_ENDPOINT_URL,
)
orders_table = _dynamodb.Table(DYNAMODB_ORDERS_TABLE)
webhook_table = _dynamodb.Table(DYNAMODB_WEBHOOK_TABLE)
installs_table = _dynamodb.Table(DYNAMODB_INSTALLS_TABLE)


def _json_safe(obj):
    """Convert DynamoDB Decimals (and nested structures) into JSON-serializable values."""
    if isinstance(obj, list):
        return [_json_safe(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, Decimal):
        # If it's an int-like decimal, return int; else float.
        if obj % 1 == 0:
            return int(obj)
        return float(obj)
    return obj

class Order(BaseModel):
    cloverOrderId: str
    amount: float
    createdAt: datetime


def _clover_hosts(region: str) -> tuple[str, str]:
    """
    Returns (authorize_host, api_host) for the given Clover region.
    - US/NA: https://www.clover.com + https://api.clover.com
    - EU:    https://www.eu.clover.com + https://api.eu.clover.com
    """
    r = (region or "us").lower()
    if r == "eu":
        return "https://www.eu.clover.com", "https://api.eu.clover.com"
    return "https://www.clover.com", "https://api.clover.com"


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def _sign_state(payload: dict) -> str:
    """
    Stateless OAuth 'state' value:
      base64url(json_payload) + "." + base64url(hmac_sha256(payload))
    Payload includes iat (issued-at) and nonce.
    """
    if not OAUTH_STATE_SECRET:
        raise RuntimeError("Missing required env var: OAUTH_STATE_SECRET")
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    body_b64 = _b64url_encode(body)
    sig = hmac.new(OAUTH_STATE_SECRET.encode("utf-8"), body_b64.encode("utf-8"), hashlib.sha256).digest()
    return f"{body_b64}.{_b64url_encode(sig)}"


def _verify_state(state: str, max_age_seconds: int = 10 * 60) -> dict:
    if not OAUTH_STATE_SECRET:
        raise HTTPException(status_code=500, detail="Server misconfigured (missing OAUTH_STATE_SECRET)")
    try:
        body_b64, sig_b64 = state.split(".", 1)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid state")
    expected = hmac.new(OAUTH_STATE_SECRET.encode("utf-8"), body_b64.encode("utf-8"), hashlib.sha256).digest()
    if not hmac.compare_digest(_b64url_encode(expected), sig_b64):
        raise HTTPException(status_code=400, detail="Invalid state")
    try:
        payload = json.loads(_b64url_decode(body_b64).decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid state")
    iat = payload.get("iat")
    if not isinstance(iat, (int, float)):
        raise HTTPException(status_code=400, detail="Invalid state")
    if time.time() - float(iat) > max_age_seconds:
        raise HTTPException(status_code=400, detail="State expired")
    return payload

def verify_api_key(x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Forbidden")
    return True


@app.get("/oauth/start")
def oauth_start():
    """
    Redirect a merchant to Clover's OAuth v2 authorization screen.

    You typically link to this from your frontend (hosted on Vercel) to initiate install/login.
    """
    if not CLOVER_CLIENT_ID:
        raise HTTPException(status_code=500, detail="Missing CLOVER_CLIENT_ID")
    if not CLOVER_REDIRECT_URI:
        raise HTTPException(status_code=500, detail="Missing CLOVER_REDIRECT_URI")

    authorize_host, _api_host = _clover_hosts(CLOVER_REGION)
    nonce = _b64url_encode(os.urandom(16))
    state = _sign_state({"iat": int(time.time()), "nonce": nonce, "region": CLOVER_REGION})

    params = {
        "client_id": CLOVER_CLIENT_ID,
        "redirect_uri": CLOVER_REDIRECT_URI,
        "response_type": "code",
        "state": state,
    }
    url = f"{authorize_host}/oauth/v2/authorize"
    return RedirectResponse(url=f"{url}?{httpx.QueryParams(params)}", status_code=302)


@app.get("/oauth/callback")
async def oauth_callback(code: Optional[str] = None, state: Optional[str] = None):
    """
    Clover redirects here with ?code=...&state=...
    Exchange code -> access_token + refresh_token, then store keyed by merchantId in DynamoDB.
    """
    if not code:
        raise HTTPException(status_code=400, detail="Missing code")
    if not state:
        raise HTTPException(status_code=400, detail="Missing state")
    if not CLOVER_CLIENT_ID or not CLOVER_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="Missing CLOVER_CLIENT_ID/CLOVER_CLIENT_SECRET")
    if not CLOVER_REDIRECT_URI:
        raise HTTPException(status_code=500, detail="Missing CLOVER_REDIRECT_URI")

    state_payload = _verify_state(state)
    region = (state_payload.get("region") or CLOVER_REGION or "us").lower()
    _authorize_host, api_host = _clover_hosts(region)

    token_url = f"{api_host}/oauth/v2/token"
    form = {
        "client_id": CLOVER_CLIENT_ID,
        "client_secret": CLOVER_CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": CLOVER_REDIRECT_URI,
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(
            token_url,
            data=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    if resp.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"Clover token exchange failed: {resp.text}")

    token = resp.json()
    access_token = token.get("access_token")
    refresh_token = token.get("refresh_token")
    expires_in = token.get("expires_in")  # seconds
    merchant_id = token.get("merchant_id") or token.get("merchantId")

    if not access_token or not refresh_token or not merchant_id:
        raise HTTPException(status_code=502, detail=f"Unexpected token response: {token}")

    now_ms = int(time.time() * 1000)
    expires_at_ms = now_ms + int(expires_in or 0) * 1000

    installs_table.put_item(
        Item={
            "merchantId": str(merchant_id),
            "region": region,
            "apiHost": api_host,
            "accessToken": str(access_token),
            "refreshToken": str(refresh_token),
            "expiresAtMs": Decimal(str(expires_at_ms)),
            "updatedAtMs": Decimal(str(now_ms)),
            "status": "active",
        }
    )

    # In a real app, redirect to your Vercel UI (e.g., /app?merchantId=...)
    return {"success": True, "merchantId": str(merchant_id)}

@app.post("/clover-webhook")  # THIS MUST MATCH EXACTLY
async def clover_webhook(request: Request):
    # DynamoDB requires Decimal for numbers; Request.json() will create floats/ints.
    raw = await request.body()
    data = json.loads(raw.decode("utf-8"), parse_float=Decimal, parse_int=Decimal)

    event_id = str(uuid4())
    received_at = datetime.utcnow().isoformat() + "Z"
    item = {
        "eventId": event_id,            # partition key (recommended for webhook table)
        "receivedAt": received_at,      # sort key (recommended for webhook table)
        "payload": data,                # full webhook payload as a DynamoDB map
    }

    # Best-effort: bubble up a useful order id field if it exists (helps querying later)
    possible_order_id = (
        data.get("cloverOrderId")
        or data.get("orderId")
        or data.get("order", {}).get("id") if isinstance(data.get("order"), dict) else None
        or data.get("id")
    )
    if possible_order_id:
        item["cloverOrderId"] = str(possible_order_id)

    webhook_table.put_item(Item=item)
    return {"success": True}

@app.get("/")
def root():
    return {"message": "Backend is running"}

def _get_install(merchant_id: str) -> dict:
    resp = installs_table.get_item(Key={"merchantId": merchant_id})
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Merchant not installed")
    if item.get("status") != "active":
        raise HTTPException(status_code=403, detail="Install not active")
    return item


async def _refresh_access_token_if_needed(merchant_id: str) -> dict:
    """
    Returns an install record with a valid access token (refreshing if near expiry).
    """
    item = _get_install(merchant_id)
    expires_at_ms = int(item.get("expiresAtMs") or 0)
    now_ms = int(time.time() * 1000)

    # Refresh if expired or within 60s of expiry
    if expires_at_ms and (expires_at_ms - now_ms) > 60_000:
        return item

    if not CLOVER_CLIENT_ID or not CLOVER_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="Missing CLOVER_CLIENT_ID/CLOVER_CLIENT_SECRET")

    api_host = item.get("apiHost") or _clover_hosts(item.get("region") or CLOVER_REGION)[1]
    refresh_url = f"{api_host}/oauth/v2/refresh"

    form = {
        "client_id": CLOVER_CLIENT_ID,
        "client_secret": CLOVER_CLIENT_SECRET,
        "refresh_token": str(item.get("refreshToken")),
        "grant_type": "refresh_token",
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(
            refresh_url,
            data=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    if resp.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"Clover refresh failed: {resp.text}")

    token = resp.json()
    access_token = token.get("access_token")
    refresh_token = token.get("refresh_token") or item.get("refreshToken")
    expires_in = int(token.get("expires_in") or 0)
    new_expires_at_ms = now_ms + expires_in * 1000

    installs_table.update_item(
        Key={"merchantId": merchant_id},
        UpdateExpression="SET accessToken=:a, refreshToken=:r, expiresAtMs=:e, updatedAtMs=:u",
        ExpressionAttributeValues={
            ":a": str(access_token),
            ":r": str(refresh_token),
            ":e": Decimal(str(new_expires_at_ms)),
            ":u": Decimal(str(now_ms)),
        },
    )

    item["accessToken"] = str(access_token)
    item["refreshToken"] = str(refresh_token)
    item["expiresAtMs"] = Decimal(str(new_expires_at_ms))
    item["updatedAtMs"] = Decimal(str(now_ms))
    return item


@app.get("/clover/merchants/{merchant_id}")
async def get_clover_merchant(merchant_id: str, _=Depends(verify_api_key)):
    """
    Example 'dashboard' API endpoint: fetch merchant info from Clover.
    Requires x-api-key to avoid exposing your Clover tokens to the public internet.
    """
    install = await _refresh_access_token_if_needed(merchant_id)
    api_host = install.get("apiHost") or _clover_hosts(install.get("region") or CLOVER_REGION)[1]
    access_token = str(install.get("accessToken"))

    url = f"{api_host}/v3/merchants/{merchant_id}"
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(url, headers={"Authorization": f"Bearer {access_token}"})
    if resp.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"Clover API error: {resp.text}")
    return resp.json()


@app.post("/orders")
def create_order(order: Order, _=Depends(verify_api_key)):
    item = {
        "cloverOrderId": order.cloverOrderId,  # partition key
        "amount": Decimal(str(order.amount)),
        "createdAt": order.createdAt.isoformat(),
    }
    try:
        orders_table.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(cloverOrderId)",
        )
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            raise HTTPException(status_code=409, detail="Order already exists")
        raise
    return {"success": True}


@app.get("/orders/{order_id}")
def get_order(order_id: str, _=Depends(verify_api_key)):
    resp = orders_table.get_item(Key={"cloverOrderId": order_id})
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Order not found")
    return _json_safe(item)

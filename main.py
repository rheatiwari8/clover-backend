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
from urllib.parse import urlencode

import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
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
# App-level multi-location config (per merchantId).
# Create this table with:
# - Partition key: merchantId (String)
# - Sort key: locationId (String)
DYNAMODB_LOCATIONS_TABLE = os.getenv("DYNAMODB_LOCATIONS_TABLE", "clover_locations")

# Clover OAuth v2 (expiring access tokens + refresh tokens).
# Docs: https://docs.clover.com/dev/docs/oauth-intro
CLOVER_CLIENT_ID = os.getenv("CLOVER_CLIENT_ID")
CLOVER_CLIENT_SECRET = os.getenv("CLOVER_CLIENT_SECRET")
CLOVER_REDIRECT_URI = os.getenv("CLOVER_REDIRECT_URI")  # e.g. https://api.myapp.com/oauth/callback
# "prod" (default) or "sandbox"
CLOVER_ENV = (os.getenv("CLOVER_ENV") or "prod").lower()
# Optional overrides (useful if Clover changes hosts or you want full control).
# - CLOVER_AUTHORIZE_HOST: where the merchant is sent for consent (OAuth authorize UI)
# - CLOVER_OAUTH_HOST: where the backend exchanges/refreshes tokens
# - CLOVER_REST_HOST: where the backend calls REST v3 endpoints (items, categories, etc)
#
# Back-compat: CLOVER_API_HOST is treated as CLOVER_OAUTH_HOST.
CLOVER_AUTHORIZE_HOST = os.getenv("CLOVER_AUTHORIZE_HOST")
CLOVER_OAUTH_HOST = os.getenv("CLOVER_OAUTH_HOST") or os.getenv("CLOVER_API_HOST")
CLOVER_REST_HOST = os.getenv("CLOVER_REST_HOST")
# "us" (default) or "eu"
CLOVER_REGION = (os.getenv("CLOVER_REGION") or "us").lower()
OAUTH_STATE_SECRET = os.getenv("OAUTH_STATE_SECRET")  # required if you use /oauth/start
FRONTEND_URL = os.getenv("FRONTEND_URL")  # optional: redirect here after successful install

# Short-lived browser session token for the built-in menu UI.
SESSION_SECRET = os.getenv("SESSION_SECRET") or OAUTH_STATE_SECRET
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS") or "3600")

# Allow your Vercel frontend (and local dev) to call this API.
# In production, replace '*' with your Vercel domain(s), e.g. "https://my-app.vercel.app"
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

def _get_tables():
    """
    Lazily create DynamoDB tables.

    On Vercel, missing env vars (e.g. AWS_REGION) can cause import-time crashes if we
    initialize boto3 at module import. This function defers initialization until
    an endpoint is called and provides a clearer error message.
    """
    try:
        dynamodb = boto3.resource(
            "dynamodb",
            region_name=AWS_REGION,
            endpoint_url=DYNAMODB_ENDPOINT_URL,
        )
        return (
            dynamodb.Table(DYNAMODB_ORDERS_TABLE),
            dynamodb.Table(DYNAMODB_WEBHOOK_TABLE),
            dynamodb.Table(DYNAMODB_INSTALLS_TABLE),
            dynamodb.Table(DYNAMODB_LOCATIONS_TABLE),
        )
    except Exception as e:
        # Surface a readable error to callers rather than crashing the whole function.
        raise HTTPException(
            status_code=500,
            detail=(
                "Server misconfigured for DynamoDB. "
                "Check AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and table env vars. "
                f"Underlying error: {type(e).__name__}: {e}"
            ),
        )


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

class LocationCreate(BaseModel):
    name: str
    locationId: Optional[str] = None  # if omitted, server generates one


class LocationMenuUpdate(BaseModel):
    itemIds: list[str]


def _clover_oauth_hosts(region: str, env: str) -> tuple[str, str]:
    """
    Returns (authorize_host, oauth_host) for the given Clover region and environment.

    Environment:
    - prod:    www/api
    - sandbox: sandbox/apisandbox (Clover's test environment)

    Region:
    - us (default)
    - eu
    """
    if CLOVER_AUTHORIZE_HOST and CLOVER_OAUTH_HOST:
        return CLOVER_AUTHORIZE_HOST.rstrip("/"), CLOVER_OAUTH_HOST.rstrip("/")

    r = (region or "us").lower()
    e = (env or "prod").lower()

    if e == "sandbox":
        # Clover sandbox commonly uses these hosts.
        # If you need a different host (e.g. EU sandbox), set CLOVER_AUTHORIZE_HOST/CLOVER_API_HOST explicitly.
        return "https://sandbox.dev.clover.com", "https://apisandbox.dev.clover.com"

    # prod
    if r == "eu":
        return "https://www.eu.clover.com", "https://api.eu.clover.com"
    return "https://www.clover.com", "https://api.clover.com"


def _clover_rest_host(region: str, env: str) -> str:
    """
    REST v3 base host.

    Observed behavior:
    - Sandbox UI + some REST calls use `https://sandbox.dev.clover.com/v3/...`
    - OAuth token/refresh uses `https://apisandbox.dev.clover.com/oauth/v2/...`

    If this ever changes, set CLOVER_REST_HOST explicitly.
    """
    if CLOVER_REST_HOST:
        return CLOVER_REST_HOST.rstrip("/")
    r = (region or "us").lower()
    e = (env or "prod").lower()
    if e == "sandbox":
        return "https://sandbox.dev.clover.com"
    if r == "eu":
        return "https://api.eu.clover.com"
    return "https://api.clover.com"


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def _try_decode_jwt_payload(token: str) -> dict:
    """
    Decode a JWT payload WITHOUT verifying signature.
    Useful to extract identifiers (e.g. merchant_uuid) when Clover omits them in the response body.
    """
    try:
        _hdr, payload_b64, _sig = (token or "").split(".", 2)
        return json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except Exception:
        return {}


def _sign_state(payload: dict) -> str:
    """
    Stateless OAuth 'state' value:
      base64url(json_payload) + "." + base64url(hmac_sha256(payload))
    Payload includes iat (issued-at) and nonce.
    """
    if not OAUTH_STATE_SECRET:
        # Raise an HTTPException so Vercel/FastAPI returns a useful JSON body
        # instead of a generic "Internal Server Error".
        raise HTTPException(status_code=500, detail="Server misconfigured (missing OAUTH_STATE_SECRET)")
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


def _sign_session(payload: dict) -> str:
    """
    Short-lived browser session token for the built-in /menu UI.
    Format is identical to OAuth state: base64url(json) + "." + base64url(hmac).
    """
    if not SESSION_SECRET:
        raise RuntimeError("Missing required env var: SESSION_SECRET (or OAUTH_STATE_SECRET)")
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    body_b64 = _b64url_encode(body)
    sig = hmac.new(SESSION_SECRET.encode("utf-8"), body_b64.encode("utf-8"), hashlib.sha256).digest()
    return f"{body_b64}.{_b64url_encode(sig)}"


def _verify_session(token: str) -> dict:
    if not SESSION_SECRET:
        raise HTTPException(status_code=500, detail="Server misconfigured (missing SESSION_SECRET)")
    try:
        body_b64, sig_b64 = token.split(".", 1)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid session token")
    expected = hmac.new(SESSION_SECRET.encode("utf-8"), body_b64.encode("utf-8"), hashlib.sha256).digest()
    if not hmac.compare_digest(_b64url_encode(expected), sig_b64):
        raise HTTPException(status_code=400, detail="Invalid session token")
    try:
        payload = json.loads(_b64url_decode(body_b64).decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid session token")
    exp = payload.get("exp")
    if not isinstance(exp, (int, float)) or time.time() > float(exp):
        raise HTTPException(status_code=401, detail="Session expired")
    if not payload.get("merchantId"):
        raise HTTPException(status_code=400, detail="Invalid session token")
    return payload

def verify_api_key(x_api_key: str = Header(None)):
    if not API_KEY:
        # Avoid crashing the whole app at import/startup time; fail only protected endpoints.
        raise HTTPException(status_code=500, detail="Server misconfigured (missing API_KEY)")
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Forbidden")
    return True


@app.get("/debug/config")
def debug_config():
    """
    Debug helper: shows which critical env vars are present (without exposing secrets).
    """
    return {
        "clover": {
            "env": CLOVER_ENV,
            "region": CLOVER_REGION,
            "redirectUri": CLOVER_REDIRECT_URI,
            "hasClientId": bool(CLOVER_CLIENT_ID),
            "hasClientSecret": bool(CLOVER_CLIENT_SECRET),
            "hasOauthStateSecret": bool(OAUTH_STATE_SECRET),
            "authorizeHostOverride": CLOVER_AUTHORIZE_HOST,
            "oauthHostOverride": CLOVER_OAUTH_HOST,
            "restHostOverride": CLOVER_REST_HOST,
        },
        "aws": {
            "region": AWS_REGION,
            "ordersTable": DYNAMODB_ORDERS_TABLE,
            "webhookTable": DYNAMODB_WEBHOOK_TABLE,
            "installsTable": DYNAMODB_INSTALLS_TABLE,
            "locationsTable": DYNAMODB_LOCATIONS_TABLE,
        },
    }


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

    authorize_host, _oauth_host = _clover_oauth_hosts(CLOVER_REGION, CLOVER_ENV)
    nonce = _b64url_encode(os.urandom(16))
    state = _sign_state(
        {"iat": int(time.time()), "nonce": nonce, "region": CLOVER_REGION, "env": CLOVER_ENV}
    )

    params = {
        "client_id": CLOVER_CLIENT_ID,
        "redirect_uri": CLOVER_REDIRECT_URI,
        "response_type": "code",
        "state": state,
    }
    url = f"{authorize_host}/oauth/v2/authorize"
    return RedirectResponse(url=f"{url}?{httpx.QueryParams(params)}", status_code=302)


@app.get("/oauth/callback")
async def oauth_callback(
    request: Request, code: Optional[str] = None, state: Optional[str] = None, format: Optional[str] = None
):
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
    env = (state_payload.get("env") or CLOVER_ENV or "prod").lower()
    _authorize_host, oauth_host = _clover_oauth_hosts(region, env)
    rest_host = _clover_rest_host(region, env)

    token_url = f"{oauth_host}/oauth/v2/token"
    form = {
        "client_id": CLOVER_CLIENT_ID,
        "client_secret": CLOVER_CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": CLOVER_REDIRECT_URI,
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        # OAuth servers typically expect x-www-form-urlencoded.
        # Try form encoding first, then fall back to JSON if Clover returns 415.
        resp = await client.post(
            token_url,
            data=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if resp.status_code == 415:
            resp = await client.post(token_url, json=form)

    if resp.status_code >= 400:
        raise HTTPException(
            status_code=502,
            detail=(
                "Clover token exchange failed. "
                f"env={env} region={region} token_url={token_url} redirect_uri={CLOVER_REDIRECT_URI}. "
                f"response={resp.text}"
            ),
        )

    token = resp.json()
    access_token = token.get("access_token")
    refresh_token = token.get("refresh_token")
    # Clover responses vary by app type / platform:
    # - Some return `expires_in` + `merchant_id`
    # - Others return `access_token_expiration` (epoch seconds) + `merchant_uuid`
    expires_in = token.get("expires_in")  # seconds (optional)
    access_token_expiration = token.get("access_token_expiration")  # epoch seconds (optional)

    jwt_payload = _try_decode_jwt_payload(access_token) if access_token else {}
    merchant_id = (
        token.get("merchant_id")
        or token.get("merchantId")
        or token.get("merchant_uuid")
        or jwt_payload.get("merchant_uuid")
        or jwt_payload.get("merchantId")
        or jwt_payload.get("merchant_id")
    )

    if not access_token or not refresh_token or not merchant_id:
        raise HTTPException(
            status_code=502,
            detail=(
                "Unexpected token response (missing access_token/refresh_token/merchant id). "
                f"Keys received: {sorted(list(token.keys()))}"
            ),
        )

    now_ms = int(time.time() * 1000)
    if access_token_expiration:
        # epoch seconds -> ms
        expires_at_ms = int(access_token_expiration) * 1000
    else:
        expires_at_ms = now_ms + int(expires_in or 0) * 1000

    _orders_table, _webhook_table, installs_table, _locations_table = _get_tables()
    installs_table.put_item(
        Item={
            "merchantId": str(merchant_id),
            "env": env,
            "region": region,
            "oauthHost": oauth_host,
            "restHost": rest_host,
            "accessToken": str(access_token),
            "refreshToken": str(refresh_token),
            "expiresAtMs": Decimal(str(expires_at_ms)),
            "updatedAtMs": Decimal(str(now_ms)),
            "status": "active",
        }
    )

    # Create a short-lived session token for the merchant UI.
    session = _sign_session(
        {"merchantId": str(merchant_id), "exp": int(time.time()) + SESSION_TTL_SECONDS}
    )

    # Redirect to your UI if configured; otherwise redirect to the built-in /menu page.
    accept = (request.headers.get("accept") or "").lower()
    wants_json = (format == "json") or ("application/json" in accept)
    if FRONTEND_URL:
        base = FRONTEND_URL.rstrip("/")
        qs = urlencode({"merchantId": str(merchant_id), "session": session})
        return RedirectResponse(url=f"{base}/app?{qs}", status_code=302)

    if wants_json:
        return {"success": True, "merchantId": str(merchant_id), "session": session}

    # Default: send the merchant to the built-in menu UI.
    return RedirectResponse(
        url=f"/menu?{urlencode({'merchantId': str(merchant_id), 'session': session})}",
        status_code=302,
    )

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

    _orders_table, webhook_table, _installs_table, _locations_table = _get_tables()
    webhook_table.put_item(Item=item)
    return {"success": True}

@app.get("/")
def root():
    frontend = (FRONTEND_URL or "").rstrip("/")
    api_key_hint = "Set API_KEY in your environment" if not API_KEY else "Send x-api-key: <your API key>"

    html = f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Clover Backend API</title>
    <style>
      :root {{
        --bg: #0b1220;
        --panel: rgba(255, 255, 255, 0.06);
        --panel2: rgba(255, 255, 255, 0.08);
        --border: rgba(255, 255, 255, 0.10);
        --text: rgba(255, 255, 255, 0.92);
        --muted: rgba(255, 255, 255, 0.70);
        --muted2: rgba(255, 255, 255, 0.55);
        --accent: #7c3aed;
        --accent2: #22c55e;
        --danger: #ef4444;
        --shadow: 0 24px 80px rgba(0,0,0,0.45);
        --radius: 18px;
      }}
      * {{ box-sizing: border-box; }}
      body {{
        margin: 0;
        font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, "Apple Color Emoji", "Segoe UI Emoji";
        background:
          radial-gradient(1200px 500px at 18% 10%, rgba(124, 58, 237, 0.35), transparent 60%),
          radial-gradient(900px 480px at 90% 12%, rgba(34, 197, 94, 0.22), transparent 55%),
          radial-gradient(900px 480px at 50% 90%, rgba(59, 130, 246, 0.20), transparent 60%),
          var(--bg);
        color: var(--text);
        min-height: 100vh;
      }}
      a {{ color: inherit; }}
      .wrap {{
        max-width: 1040px;
        margin: 0 auto;
        padding: 44px 20px 72px;
      }}
      .top {{
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        margin-bottom: 32px;
      }}
      .badge {{
        display: inline-flex;
        align-items: center;
        gap: 10px;
        padding: 10px 14px;
        border: 1px solid var(--border);
        border-radius: 999px;
        background: rgba(255, 255, 255, 0.04);
        backdrop-filter: blur(10px);
      }}
      .dot {{
        width: 10px;
        height: 10px;
        border-radius: 999px;
        background: var(--accent2);
        box-shadow: 0 0 0 6px rgba(34, 197, 94, 0.12);
      }}
      .grid {{
        display: grid;
        grid-template-columns: 1.3fr 0.7fr;
        gap: 18px;
      }}
      @media (max-width: 900px) {{
        .grid {{ grid-template-columns: 1fr; }}
      }}
      .card {{
        background: linear-gradient(180deg, rgba(255, 255, 255, 0.06), rgba(255, 255, 255, 0.04));
        border: 1px solid var(--border);
        border-radius: var(--radius);
        box-shadow: var(--shadow);
        overflow: hidden;
      }}
      .card .hd {{
        padding: 18px 18px 0;
      }}
      .card .bd {{
        padding: 18px;
      }}
      h1 {{
        margin: 0;
        font-size: 34px;
        line-height: 1.15;
        letter-spacing: -0.02em;
      }}
      p {{
        margin: 10px 0 0;
        color: var(--muted);
        line-height: 1.55;
      }}
      .actions {{
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        margin-top: 16px;
      }}
      .btn {{
        display: inline-flex;
        align-items: center;
        gap: 10px;
        padding: 10px 12px;
        border-radius: 12px;
        border: 1px solid var(--border);
        background: rgba(255, 255, 255, 0.06);
        text-decoration: none;
        color: var(--text);
        transition: transform 120ms ease, background 120ms ease, border-color 120ms ease;
        user-select: none;
      }}
      .btn:hover {{
        transform: translateY(-1px);
        background: rgba(255, 255, 255, 0.10);
        border-color: rgba(255, 255, 255, 0.16);
      }}
      .btn.primary {{
        background: linear-gradient(135deg, rgba(124, 58, 237, 0.95), rgba(99, 102, 241, 0.95));
        border-color: rgba(255, 255, 255, 0.18);
      }}
      .btn.primary:hover {{
        background: linear-gradient(135deg, rgba(124, 58, 237, 1), rgba(99, 102, 241, 1));
      }}
      .btn.good {{
        background: linear-gradient(135deg, rgba(34, 197, 94, 0.90), rgba(16, 185, 129, 0.90));
        border-color: rgba(255, 255, 255, 0.18);
      }}
      .btn.good:hover {{
        background: linear-gradient(135deg, rgba(34, 197, 94, 1), rgba(16, 185, 129, 1));
      }}
      .mono {{
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      }}
      .code {{
        background: rgba(0,0,0,0.30);
        border: 1px solid rgba(255,255,255,0.10);
        border-radius: 14px;
        padding: 12px 12px;
        overflow: auto;
        color: rgba(255,255,255,0.88);
        line-height: 1.5;
      }}
      .meta {{
        display: grid;
        grid-template-columns: 1fr;
        gap: 12px;
      }}
      .kv {{
        padding: 14px;
        border-radius: 14px;
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid rgba(255, 255, 255, 0.10);
      }}
      .k {{
        font-size: 12px;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        color: var(--muted2);
      }}
      .v {{
        margin-top: 6px;
        font-size: 14px;
        color: var(--text);
      }}
      .footer {{
        margin-top: 18px;
        color: var(--muted2);
        font-size: 13px;
      }}
      .copy {{
        float: right;
        font-size: 12px;
        padding: 6px 10px;
        border-radius: 10px;
        border: 1px solid rgba(255,255,255,0.14);
        background: rgba(255,255,255,0.06);
        color: var(--text);
        cursor: pointer;
      }}
      .copy:hover {{
        background: rgba(255,255,255,0.10);
      }}
    </style>
  </head>
  <body>
    <div class="wrap">
      <div class="top">
        <div class="badge">
          <span class="dot"></span>
          <span><strong>FastAPI</strong> backend is running</span>
        </div>
        <div class="badge mono">/ (root)</div>
      </div>

      <div class="grid">
        <div class="card">
          <div class="hd">
            <h1>Clover Dashboard API</h1>
            <p>OAuth install flow + DynamoDB storage + example endpoints for calling Clover APIs.</p>
            <div class="actions">
              <a class="btn primary" href="/docs">Open Swagger docs</a>
              <a class="btn" href="/redoc">Open ReDoc</a>
              <a class="btn" href="/oauth/start">Start OAuth install</a>
              {f'<a class="btn good" href="{frontend}/app">Open frontend</a>' if frontend else ''}
            </div>
          </div>
          <div class="bd">
            <div class="code mono" id="curlBlock">
              <button class="copy" id="copyBtn" type="button">Copy</button>
              <div style="opacity:.88; margin-bottom: 8px;">Example call (replace <span class="mono">&lt;merchantId&gt;</span> + key):</div>
              <div>curl -s \\\n  -H "x-api-key: YOUR_API_KEY" \\\n  "{'{'}{'}'}request.host_url{'}'}clover/merchants/&lt;merchantId&gt;"</div>
            </div>
            <div class="footer">
              Tip: keep secrets server-side. Your frontend should call this API; it should never hold Clover client secrets.
            </div>
          </div>
        </div>

        <div class="card">
          <div class="bd">
            <div class="meta">
              <div class="kv">
                <div class="k">Frontend URL</div>
                <div class="v mono">{frontend or "Not configured (set FRONTEND_URL)"}</div>
              </div>
              <div class="kv">
                <div class="k">API key</div>
                <div class="v">{api_key_hint}</div>
              </div>
              <div class="kv">
                <div class="k">Next step</div>
                <div class="v">Build your UI in Next.js (Vercel), then call this API from the browser.</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <script>
      (function () {{
        var btn = document.getElementById("copyBtn");
        var block = document.getElementById("curlBlock");
        if (!btn || !block) return;
        btn.addEventListener("click", async function () {{
          var text = block.innerText.replace("Copy\\n", "");
          try {{
            await navigator.clipboard.writeText(text);
            btn.textContent = "Copied";
            setTimeout(function() {{ btn.textContent = "Copy"; }}, 1100);
          }} catch (e) {{
            btn.textContent = "Select + copy";
            setTimeout(function() {{ btn.textContent = "Copy"; }}, 1600);
          }}
        }});
      }})();
    </script>
  </body>
</html>"""

    return HTMLResponse(content=html, status_code=200)


@app.get("/menu")
def menu_page(merchantId: Optional[str] = None, session: Optional[str] = None):
    """
    Built-in minimal UI to browse Clover inventory items and select them into a cart.

    Access:
    - You typically land here after OAuth install (we redirect here by default).
    - Requires `session` query param (short-lived signed token).
    """
    if not session:
        raise HTTPException(status_code=400, detail="Missing session")
    payload = _verify_session(session)
    mid = str(payload["merchantId"])
    if merchantId and merchantId != mid:
        raise HTTPException(status_code=400, detail="merchantId mismatch")

    html = f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Clover Menu</title>
    <style>
      :root {{
        --bg: #0b1220;
        --panel: rgba(255, 255, 255, 0.06);
        --panel2: rgba(255, 255, 255, 0.08);
        --border: rgba(255, 255, 255, 0.10);
        --text: rgba(255, 255, 255, 0.92);
        --muted: rgba(255, 255, 255, 0.70);
        --accent: #7c3aed;
        --accent2: #22c55e;
        --danger: #ef4444;
        --shadow: 0 24px 80px rgba(0,0,0,0.45);
        --radius: 18px;
      }}
      * {{ box-sizing: border-box; }}
      body {{
        margin: 0;
        font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
        background:
          radial-gradient(1200px 500px at 18% 10%, rgba(124, 58, 237, 0.35), transparent 60%),
          radial-gradient(900px 480px at 90% 12%, rgba(34, 197, 94, 0.22), transparent 55%),
          radial-gradient(900px 480px at 50% 90%, rgba(59, 130, 246, 0.20), transparent 60%),
          var(--bg);
        color: var(--text);
        min-height: 100vh;
      }}
      .wrap {{
        max-width: 1180px;
        margin: 0 auto;
        padding: 34px 18px 70px;
      }}
      .top {{
        display: flex;
        align-items: flex-end;
        justify-content: space-between;
        gap: 14px;
        margin-bottom: 18px;
      }}
      h1 {{
        margin: 0;
        font-size: 30px;
        letter-spacing: -0.02em;
      }}
      .sub {{
        margin-top: 8px;
        color: var(--muted);
        line-height: 1.5;
        font-size: 14px;
      }}
      .grid {{
        display: grid;
        grid-template-columns: 1.2fr 0.8fr;
        gap: 16px;
      }}
      @media (max-width: 980px) {{
        .grid {{ grid-template-columns: 1fr; }}
      }}
      .card {{
        background: linear-gradient(180deg, rgba(255, 255, 255, 0.06), rgba(255, 255, 255, 0.04));
        border: 1px solid var(--border);
        border-radius: var(--radius);
        box-shadow: var(--shadow);
        overflow: hidden;
      }}
      .hd {{
        padding: 16px 16px 0;
      }}
      .bd {{
        padding: 16px;
      }}
      .row {{
        display: flex;
        gap: 10px;
        align-items: center;
        flex-wrap: wrap;
      }}
      input[type="text"] {{
        flex: 1;
        min-width: 220px;
        padding: 10px 12px;
        border-radius: 12px;
        border: 1px solid var(--border);
        background: rgba(255,255,255,0.04);
        color: var(--text);
        outline: none;
      }}
      button {{
        padding: 10px 12px;
        border-radius: 12px;
        border: 1px solid var(--border);
        background: rgba(255,255,255,0.06);
        color: var(--text);
        cursor: pointer;
      }}
      button.primary {{
        background: linear-gradient(180deg, rgba(124, 58, 237, 0.95), rgba(124, 58, 237, 0.72));
        border-color: rgba(124, 58, 237, 0.55);
      }}
      button.good {{
        background: linear-gradient(180deg, rgba(34, 197, 94, 0.95), rgba(34, 197, 94, 0.72));
        border-color: rgba(34, 197, 94, 0.55);
      }}
      .list {{
        display: grid;
        gap: 10px;
      }}
      .item {{
        display: grid;
        grid-template-columns: 1fr auto;
        gap: 10px;
        padding: 12px;
        border-radius: 14px;
        border: 1px solid var(--border);
        background: rgba(255,255,255,0.03);
      }}
      .name {{
        font-weight: 650;
        margin-bottom: 4px;
      }}
      .meta {{
        color: var(--muted);
        font-size: 13px;
        line-height: 1.4;
      }}
      .pill {{
        display: inline-flex;
        padding: 4px 8px;
        border-radius: 999px;
        border: 1px solid var(--border);
        background: rgba(255,255,255,0.03);
        font-size: 12px;
        color: var(--muted);
        margin-right: 6px;
      }}
      .err {{
        color: #fecaca;
        background: rgba(239, 68, 68, 0.16);
        border: 1px solid rgba(239, 68, 68, 0.25);
        padding: 10px 12px;
        border-radius: 14px;
        white-space: pre-wrap;
      }}
      .cartLine {{
        display: grid;
        grid-template-columns: 1fr auto;
        gap: 8px;
        padding: 10px 0;
        border-bottom: 1px solid rgba(255,255,255,0.08);
      }}
      .cartLine:last-child {{ border-bottom: none; }}
      .tot {{
        display: flex;
        justify-content: space-between;
        margin-top: 12px;
        padding-top: 12px;
        border-top: 1px solid rgba(255,255,255,0.10);
        font-weight: 700;
      }}
    </style>
  </head>
  <body>
    <div class="wrap">
      <div class="top">
        <div>
          <h1>Menu</h1>
          <div class="sub">Merchant: <span class="pill">{mid}</span> — loading items from Clover…</div>
        </div>
        <div class="row">
          <button id="reloadBtn" class="primary">Reload</button>
          <a href="/"><button>Home</button></a>
        </div>
      </div>

      <div class="grid">
        <div class="card">
          <div class="hd">
            <div class="row">
              <input id="search" type="text" placeholder="Search items…" />
              <span id="count" class="pill">0 items</span>
            </div>
          </div>
          <div class="bd">
            <div id="error" class="err" style="display:none"></div>
            <div id="items" class="list"></div>
          </div>
        </div>

        <div class="card">
          <div class="hd">
            <div class="row" style="justify-content: space-between;">
              <div style="font-weight:700">Selected</div>
              <button id="clearBtn">Clear</button>
            </div>
          </div>
          <div class="bd">
            <div id="cart"></div>
            <div class="tot">
              <div>Total</div>
              <div id="total">$0.00</div>
            </div>
            <div class="sub" style="margin-top:10px">
              This is a “selection/cart” UI. Next step is wiring a “Create order” flow if you want checkout.
            </div>
          </div>
        </div>
      </div>
    </div>

    <script>
      const SESSION = {json.dumps(session)};
      const MERCHANT_ID = {json.dumps(mid)};
      const itemsEl = document.getElementById("items");
      const cartEl = document.getElementById("cart");
      const totalEl = document.getElementById("total");
      const countEl = document.getElementById("count");
      const errEl = document.getElementById("error");
      const searchEl = document.getElementById("search");

      let allItems = [];
      let cart = JSON.parse(localStorage.getItem("cloverCart:" + MERCHANT_ID) || "{{}}");

      function centsToDollars(cents) {{
        if (cents === null || cents === undefined) return "";
        const n = Number(cents);
        if (!Number.isFinite(n)) return "";
        return "$" + (n / 100).toFixed(2);
      }}

      function getItemPrice(item) {{
        // Clover items often have `price` in cents.
        return Number(item.price || 0);
      }}

      function renderCart() {{
        const lines = Object.values(cart);
        if (!lines.length) {{
          cartEl.innerHTML = '<div class="meta">No items selected.</div>';
          totalEl.textContent = "$0.00";
          return;
        }}
        let total = 0;
        cartEl.innerHTML = lines.map(line => {{
          total += line.qty * line.price;
          return `
            <div class="cartLine">
              <div>
                <div class="name">${{line.name}}</div>
                <div class="meta">${{centsToDollars(line.price)}} × ${{line.qty}}</div>
              </div>
              <div class="row" style="justify-content:flex-end">
                <button data-dec="${{line.id}}">−</button>
                <button data-inc="${{line.id}}">+</button>
              </div>
            </div>
          `;
        }}).join("");
        totalEl.textContent = centsToDollars(total);
        localStorage.setItem("cloverCart:" + MERCHANT_ID, JSON.stringify(cart));
      }}

      function renderItems(filterText) {{
        const q = (filterText || "").toLowerCase().trim();
        const list = q ? allItems.filter(it => (it.name || "").toLowerCase().includes(q)) : allItems;
        countEl.textContent = `${{list.length}} items`;
        itemsEl.innerHTML = list.map(it => {{
          const price = getItemPrice(it);
          const id = it.id || it.uuid || it.itemId;
          const name = it.name || "(unnamed)";
          const code = it.code ? `<span class="pill">code: ${{it.code}}</span>` : "";
          const priceStr = price ? `<span class="pill">${{centsToDollars(price)}}</span>` : `<span class="pill">no price</span>`;
          return `
            <div class="item">
              <div>
                <div class="name">${{name}}</div>
                <div class="meta">${{priceStr}} ${{code}}</div>
              </div>
              <div class="row" style="justify-content:flex-end">
                <button class="good" data-add="${{id}}" data-name="${{encodeURIComponent(name)}}" data-price="${{price}}">Add</button>
              </div>
            </div>
          `;
        }}).join("");
      }}

      function showError(msg) {{
        errEl.style.display = "block";
        errEl.textContent = msg;
      }}

      async function loadItems() {{
        errEl.style.display = "none";
        itemsEl.innerHTML = '<div class="meta">Loading…</div>';
        try {{
          const res = await fetch(`/clover/menu/items?session=${{encodeURIComponent(SESSION)}}`);
          const text = await res.text();
          if (!res.ok) throw new Error(text || ("HTTP " + res.status));
          const data = JSON.parse(text);
          const els = Array.isArray(data) ? data : (data.elements || []);
          allItems = els;
          renderItems(searchEl.value);
        }} catch (e) {{
          showError(String(e && e.message ? e.message : e));
          itemsEl.innerHTML = "";
        }}
      }}

      document.getElementById("reloadBtn").addEventListener("click", loadItems);
      document.getElementById("clearBtn").addEventListener("click", function() {{
        cart = {{}};
        renderCart();
      }});
      searchEl.addEventListener("input", function() {{
        renderItems(searchEl.value);
      }});
      document.body.addEventListener("click", function(e) {{
        const t = e.target;
        if (!t) return;
        const add = t.getAttribute("data-add");
        const inc = t.getAttribute("data-inc");
        const dec = t.getAttribute("data-dec");

        if (add) {{
          const id = add;
          const name = decodeURIComponent(t.getAttribute("data-name") || "");
          const price = Number(t.getAttribute("data-price") || 0);
          cart[id] = cart[id] || {{ id, name, price, qty: 0 }};
          cart[id].qty += 1;
          renderCart();
        }}
        if (inc) {{
          cart[inc].qty += 1;
          renderCart();
        }}
        if (dec) {{
          cart[dec].qty -= 1;
          if (cart[dec].qty <= 0) delete cart[dec];
          renderCart();
        }}
      }});

      renderCart();
      loadItems();
    </script>
  </body>
</html>"""

    return HTMLResponse(content=html, status_code=200)

def _get_install(merchant_id: str) -> dict:
    _orders_table, _webhook_table, installs_table, _locations_table = _get_tables()
    resp = installs_table.get_item(Key={"merchantId": merchant_id})
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Merchant not installed")
    if item.get("status") != "active":
        raise HTTPException(status_code=403, detail="Install not active")
    return item


def _resolve_merchant_id_for_browser_or_api(
    merchant_id: Optional[str],
    session: Optional[str],
    x_api_key: Optional[str],
) -> str:
    """
    Access control for endpoints that may be called by:
    - a browser (using a short-lived signed `session` token), OR
    - a trusted server/client (using `x-api-key`)
    """
    if session:
        payload = _verify_session(session)
        mid = str(payload["merchantId"])
        if merchant_id and merchant_id != mid:
            raise HTTPException(status_code=400, detail="merchantId mismatch")
        return mid

    # No session token => require API key.
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Forbidden")
    if not merchant_id:
        raise HTTPException(status_code=400, detail="Missing merchantId")
    return merchant_id


def _require_location_id(location_id: Optional[str]) -> str:
    if not location_id:
        raise HTTPException(status_code=400, detail="Missing locationId")
    return location_id


@app.get("/tenant/locations")
async def list_locations(
    merchantId: Optional[str] = None,
    session: Optional[str] = None,
    x_api_key: Optional[str] = Header(None),
):
    """
    List app-defined locations for a Clover merchant (tenant).
    """
    merchant_id = _resolve_merchant_id_for_browser_or_api(merchantId, session, x_api_key)
    _orders_table, _webhook_table, _installs_table, locations_table = _get_tables()

    try:
        resp = locations_table.query(
            KeyConditionExpression=Key("merchantId").eq(merchant_id),
        )
    except ClientError as e:
        raise HTTPException(
            status_code=500,
            detail=f"DynamoDB query failed for locations table '{DYNAMODB_LOCATIONS_TABLE}': {e.response.get('Error')}",
        )
    items = resp.get("Items") or []
    # Only return location records (not necessarily future metadata)
    return {"elements": [_json_safe(x) for x in items]}


@app.post("/tenant/locations")
async def create_location(
    body: LocationCreate,
    merchantId: Optional[str] = None,
    session: Optional[str] = None,
    x_api_key: Optional[str] = Header(None),
):
    """
    Create an app-defined location under a merchant.
    """
    merchant_id = _resolve_merchant_id_for_browser_or_api(merchantId, session, x_api_key)
    _orders_table, _webhook_table, _installs_table, locations_table = _get_tables()

    location_id = body.locationId or str(uuid4())
    now_ms = int(time.time() * 1000)
    item = {
        "merchantId": merchant_id,
        "locationId": location_id,
        "name": body.name,
        "createdAtMs": Decimal(str(now_ms)),
        "updatedAtMs": Decimal(str(now_ms)),
    }
    try:
        locations_table.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(merchantId) AND attribute_not_exists(locationId)",
        )
    except ClientError as e:
        raise HTTPException(
            status_code=500,
            detail=f"DynamoDB put_item failed for locations table '{DYNAMODB_LOCATIONS_TABLE}': {e.response.get('Error')}",
        )
    return _json_safe(item)


@app.get("/tenant/locations/{location_id}")
async def get_location(
    location_id: str,
    merchantId: Optional[str] = None,
    session: Optional[str] = None,
    x_api_key: Optional[str] = Header(None),
):
    merchant_id = _resolve_merchant_id_for_browser_or_api(merchantId, session, x_api_key)
    _orders_table, _webhook_table, _installs_table, locations_table = _get_tables()
    try:
        resp = locations_table.get_item(Key={"merchantId": merchant_id, "locationId": location_id})
    except ClientError as e:
        raise HTTPException(
            status_code=500,
            detail=f"DynamoDB get_item failed for locations table '{DYNAMODB_LOCATIONS_TABLE}': {e.response.get('Error')}",
        )
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Location not found")
    return _json_safe(item)


@app.put("/tenant/locations/{location_id}/menu")
async def set_location_menu(
    location_id: str,
    body: LocationMenuUpdate,
    merchantId: Optional[str] = None,
    session: Optional[str] = None,
    x_api_key: Optional[str] = Header(None),
):
    """
    Set the menu allowlist for a location (list of Clover item IDs).
    """
    merchant_id = _resolve_merchant_id_for_browser_or_api(merchantId, session, x_api_key)
    _orders_table, _webhook_table, _installs_table, locations_table = _get_tables()

    item_ids = [str(x) for x in (body.itemIds or [])]
    now_ms = int(time.time() * 1000)
    try:
        locations_table.update_item(
            Key={"merchantId": merchant_id, "locationId": location_id},
            UpdateExpression="SET itemIds=:i, updatedAtMs=:u",
            ExpressionAttributeValues={":i": item_ids, ":u": Decimal(str(now_ms))},
        )
    except ClientError as e:
        raise HTTPException(
            status_code=500,
            detail=f"DynamoDB update_item failed for locations table '{DYNAMODB_LOCATIONS_TABLE}': {e.response.get('Error')}",
        )
    return {"success": True, "merchantId": merchant_id, "locationId": location_id, "itemIdsCount": len(item_ids)}


@app.get("/tenant/locations/{location_id}/menu")
async def get_location_menu(
    location_id: str,
    merchantId: Optional[str] = None,
    session: Optional[str] = None,
    x_api_key: Optional[str] = Header(None),
):
    """
    Get the menu allowlist for a location.
    """
    merchant_id = _resolve_merchant_id_for_browser_or_api(merchantId, session, x_api_key)
    _orders_table, _webhook_table, _installs_table, locations_table = _get_tables()
    try:
        resp = locations_table.get_item(Key={"merchantId": merchant_id, "locationId": location_id})
    except ClientError as e:
        raise HTTPException(
            status_code=500,
            detail=f"DynamoDB get_item failed for locations table '{DYNAMODB_LOCATIONS_TABLE}': {e.response.get('Error')}",
        )
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Location not found")
    return {"merchantId": merchant_id, "locationId": location_id, "itemIds": item.get("itemIds") or []}


@app.get("/clover/menu/items")
async def clover_menu_items(
    merchantId: Optional[str] = None,
    session: Optional[str] = None,
    locationId: Optional[str] = None,
    limit: int = 100,
    cursor: Optional[str] = None,
    x_api_key: Optional[str] = Header(None),
):
    """
    Return Clover inventory/menu items for a merchant.

    Notes:
    - Requires your Clover app to have Inventory/Items READ scope.
    - Clover responses are typically { "elements": [...], "cursor": "..." }.
    """
    merchant_id = _resolve_merchant_id_for_browser_or_api(merchantId, session, x_api_key)
    install = await _refresh_access_token_if_needed(merchant_id)
    rest_host = install.get("restHost") or _clover_rest_host(
        install.get("region") or CLOVER_REGION, install.get("env") or CLOVER_ENV
    )
    access_token = str(install.get("accessToken"))

    # If a locationId is specified, filter items by the app-defined allowlist for that location.
    allowlist: Optional[set[str]] = None
    if locationId:
        _orders_table, _webhook_table, _installs_table, locations_table = _get_tables()
        loc = locations_table.get_item(Key={"merchantId": merchant_id, "locationId": locationId}).get("Item")
        if not loc:
            raise HTTPException(status_code=404, detail="Location not found")
        ids = loc.get("itemIds") or []
        if ids:
            allowlist = {str(x) for x in ids}

    params = {"limit": max(1, min(int(limit), 1000))}
    if cursor:
        params["cursor"] = cursor

    url = f"{rest_host}/v3/merchants/{merchant_id}/items"
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(url, headers={"Authorization": f"Bearer {access_token}"}, params=params)
    if resp.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"Clover API error: {resp.text}")
    data = resp.json()

    # Clover typically returns { elements: [...], cursor: "..." }
    if allowlist is not None:
        elements = data.get("elements") if isinstance(data, dict) else None
        if isinstance(elements, list):
            data["elements"] = [e for e in elements if str((e or {}).get("id")) in allowlist]
    return data


@app.get("/clover/menu/categories")
async def clover_menu_categories(
    merchantId: Optional[str] = None,
    session: Optional[str] = None,
    limit: int = 100,
    cursor: Optional[str] = None,
    x_api_key: Optional[str] = Header(None),
):
    """
    Return Clover categories (useful to group menu items).
    """
    merchant_id = _resolve_merchant_id_for_browser_or_api(merchantId, session, x_api_key)
    install = await _refresh_access_token_if_needed(merchant_id)
    rest_host = install.get("restHost") or _clover_rest_host(
        install.get("region") or CLOVER_REGION, install.get("env") or CLOVER_ENV
    )
    access_token = str(install.get("accessToken"))

    params = {"limit": max(1, min(int(limit), 1000))}
    if cursor:
        params["cursor"] = cursor

    url = f"{rest_host}/v3/merchants/{merchant_id}/categories"
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(url, headers={"Authorization": f"Bearer {access_token}"}, params=params)
    if resp.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"Clover API error: {resp.text}")
    return resp.json()


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

    oauth_host = item.get("oauthHost") or _clover_oauth_hosts(
        item.get("region") or CLOVER_REGION, item.get("env") or CLOVER_ENV
    )[1]
    refresh_url = f"{oauth_host}/oauth/v2/refresh"

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
        if resp.status_code == 415:
            resp = await client.post(refresh_url, json=form)
    if resp.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"Clover refresh failed: {resp.text}")

    token = resp.json()
    access_token = token.get("access_token")
    refresh_token = token.get("refresh_token") or item.get("refreshToken")

    expires_in = int(token.get("expires_in") or 0)
    access_token_expiration = token.get("access_token_expiration")
    if access_token_expiration:
        new_expires_at_ms = int(access_token_expiration) * 1000
    else:
        new_expires_at_ms = now_ms + expires_in * 1000

    _orders_table, _webhook_table, installs_table, _locations_table = _get_tables()
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
    rest_host = install.get("restHost") or _clover_rest_host(
        install.get("region") or CLOVER_REGION, install.get("env") or CLOVER_ENV
    )
    access_token = str(install.get("accessToken"))

    url = f"{rest_host}/v3/merchants/{merchant_id}"
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
        orders_table, _webhook_table, _installs_table, _locations_table = _get_tables()
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
    orders_table, _webhook_table, _installs_table, _locations_table = _get_tables()
    resp = orders_table.get_item(Key={"cloverOrderId": order_id})
    item = resp.get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Order not found")
    return _json_safe(item)

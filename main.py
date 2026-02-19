import os
from datetime import datetime
from decimal import Decimal
import json
import base64
import hashlib
import hmac
import time
from uuid import uuid4

# Deployment trigger - latest commit
from typing import Optional, List, Tuple
from urllib.parse import urlencode

import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Query, Query
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
    # Use typing.List for compatibility with older Python runtimes (in case Vercel ignores runtime pin).
    itemIds: List[str]


def _clover_oauth_hosts(region: str, env: str) -> Tuple[str, str]:
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


@app.get("/")
def health_check():
    """Simple health check that doesn't touch AWS or any external services."""
    return {"status": "ok", "message": "Backend is running"}


@app.get("/test-modifiers-endpoint")
def test_modifiers_endpoint():
    """Test endpoint to verify deployment."""
    return {
        "status": "ok",
        "message": "Modifiers endpoint test",
        "timestamp": time.time(),
        "endpoints": {
            "items_modifiers": "/clover/items/{item_id}/modifiers",
            "check_modifiers": "/clover/check-modifiers",
            "menu_items": "/clover/menu/items"
        }
    }


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
            "hasAccessKeyId": bool(os.getenv("AWS_ACCESS_KEY_ID")),
            "hasSecretAccessKey": bool(os.getenv("AWS_SECRET_ACCESS_KEY")),
        },
    }


@app.get("/oauth/start")
def oauth_start():
    """
    Redirect a merchant to Clover's OAuth v2 authorization screen.

    You typically link to this from your frontend (hosted on Vercel) to initiate install/login.
    """
    try:
        if not CLOVER_CLIENT_ID:
            raise HTTPException(status_code=500, detail="Missing CLOVER_CLIENT_ID")
        if not CLOVER_REDIRECT_URI:
            raise HTTPException(status_code=500, detail="Missing CLOVER_REDIRECT_URI")
        if not OAUTH_STATE_SECRET:
            raise HTTPException(status_code=500, detail="Missing OAUTH_STATE_SECRET")

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
    except HTTPException:
        raise
    except Exception as e:
        # Catch any unexpected errors (e.g. import failures, runtime errors) and surface them
        raise HTTPException(
            status_code=500,
            detail=f"Unexpected error in /oauth/start: {type(e).__name__}: {str(e)}"
        )


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
    merchantId: Optional[str] = Query(None),
    session: Optional[str] = Query(None),
    locationId: Optional[str] = Query(None),
    limit: int = Query(100),
    cursor: Optional[str] = Query(None),
    checkModifiers: Optional[str] = Query(None, description="Item ID to check modifiers for"),
    x_api_key: Optional[str] = Header(None),
):
    """
    Return Clover inventory/menu items for a merchant.

    Notes:
    - Requires your Clover app to have Inventory/Items READ scope.
    - Clover responses are typically { "elements": [...], "cursor": "..." }.
    """
    # Debug: Always add this to verify code is running
    debug_info = {
        "checkModifiers_param": checkModifiers,
        "locationId_param": locationId,
        "merchantId_param": merchantId,
        "code_version": "2024-12-15-v2"
    }
    
    merchant_id = _resolve_merchant_id_for_browser_or_api(merchantId, session, x_api_key)
    install = await _refresh_access_token_if_needed(merchant_id)
    rest_host = install.get("restHost") or _clover_rest_host(
        install.get("region") or CLOVER_REGION, install.get("env") or CLOVER_ENV
    )
    access_token = str(install.get("accessToken"))

    # Increase limit to get more items (Clover default might be lower)
    params = {"limit": max(1, min(int(limit), 1000))}
    if cursor:
        params["cursor"] = cursor
    
    # Clover API: Try location-specific endpoint first if locationId is provided
    # Some Clover APIs have /locations/{locationId}/items endpoint
    if locationId and not checkModifiers:  # Skip location-specific endpoint if checking modifiers (need all items)
        # Try location-specific items endpoint first
        location_url = f"{rest_host}/v3/merchants/{merchant_id}/locations/{locationId}/items"
        async with httpx.AsyncClient(timeout=15.0) as client:
            location_resp = await client.get(location_url, headers={"Authorization": f"Bearer {access_token}"}, params=params)
        # If location-specific endpoint works, use it
        if location_resp.status_code == 200:
            loc_data = location_resp.json()
            if isinstance(loc_data, dict):
                loc_data["_debug"] = debug_info
            return loc_data
        # If 404, fall through to regular items endpoint and filter manually
    
    # Standard items endpoint
    url = f"{rest_host}/v3/merchants/{merchant_id}/items"
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(url, headers={"Authorization": f"Bearer {access_token}"}, params=params)
    if resp.status_code >= 400:
        error_text = resp.text
        try:
            error_json = resp.json()
            error_detail = error_json.get("message") or error_json.get("error") or error_text
        except:
            error_detail = error_text
        raise HTTPException(
            status_code=502, 
            detail=f"Clover API error ({resp.status_code}): {error_detail}"
        )
    
    data = resp.json()
    
    # FORCE debug info - modify the response structure to prove code is running
    if isinstance(data, dict):
        # Add debug immediately
        data["_DEBUG_CODE_RUNNING"] = True
        data["_debug_checkModifiers"] = checkModifiers
        data["_debug_locationId"] = locationId
        data["_debug_timestamp"] = time.time()
        data["_debug_code_version"] = "2024-12-15-FINAL"
    
    # If locationId is specified, filter items by location
    # Items in Clover can be associated with locations in different ways.
    # We'll try multiple strategies to match items to locations.
    if locationId:
        elements = data.get("elements") if isinstance(data, dict) else (data if isinstance(data, list) else [])
        if isinstance(elements, list) and len(elements) > 0:
            filtered = []
            # Sample first item to understand structure (for debugging)
            sample_item_keys = list(elements[0].keys()) if elements else []
            
            for item in elements:
                matched = False
                
                # Strategy 1: Check if item has "locations" array field
                item_locations = item.get("locations") or []
                if isinstance(item_locations, list) and len(item_locations) > 0:
                    for loc in item_locations:
                        loc_id = loc.get("id") if isinstance(loc, dict) else str(loc)
                        if str(loc_id) == str(locationId):
                            filtered.append(item)
                            matched = True
                            break
                
                # Strategy 2: Check single "location" or "locationId" field
                if not matched:
                    item_location_id = item.get("location") or item.get("locationId")
                    if item_location_id and str(item_location_id) == str(locationId):
                        filtered.append(item)
                        matched = True
                
                # Strategy 3: Check "itemStock" or "stock" fields that might have location associations
                if not matched:
                    item_stock = item.get("itemStock") or item.get("stock")
                    if isinstance(item_stock, list):
                        for stock in item_stock:
                            stock_location_id = stock.get("locationId") or stock.get("location") if isinstance(stock, dict) else None
                            if stock_location_id and str(stock_location_id) == str(locationId):
                                filtered.append(item)
                                matched = True
                                break
                
                # Strategy 4: If no location association found, include item (might be available at all locations)
                # This is a fallback - items without explicit location might be available everywhere
                if not matched:
                    # Only include if item has NO location fields at all
                    has_any_location_field = (
                        item.get("locations") or 
                        item.get("location") or 
                        item.get("locationId") or
                        item.get("itemStock") or
                        item.get("stock")
                    )
                    if not has_any_location_field:
                        filtered.append(item)
            
            # Update the response with filtered items
            if isinstance(data, dict):
                data["elements"] = filtered
            else:
                data = filtered
    
    # Ensure we return consistent format - FORCE debug fields to appear
    if isinstance(data, list):
        result_data = {
            "elements": data,
            "MODIFIERS_DEBUG": "CODE_IS_RUNNING_V4",
            "checkModifiers_param": str(checkModifiers),
            "timestamp": time.time()
        }
    elif isinstance(data, dict) and "elements" in data:
        # Make a copy and FORCE add debug fields
        result_data = dict(data)
        result_data["MODIFIERS_DEBUG"] = "CODE_IS_RUNNING_V4"
        result_data["checkModifiers_param"] = str(checkModifiers)
        result_data["debug_timestamp"] = time.time()
        result_data["debug_code_version"] = "2024-12-15-V4-FORCE"
    else:
        result_data = {
            "elements": [data] if data else [],
            "MODIFIERS_DEBUG": "CODE_IS_RUNNING_V4",
            "checkModifiers_param": str(checkModifiers)
        }
    
    # ALWAYS add debug info - this proves the code is running
    result_data["_debug"] = debug_info
    result_data["debug_checkModifiers_param"] = checkModifiers
    result_data["debug_locationId_param"] = locationId  
    result_data["debug_merchantId_param"] = merchantId
    result_data["debug_code_running"] = True
    
    # If checkModifiers is provided, fetch modifiers for that item
    if checkModifiers:
        result_data["debug_checkModifiers_received"] = checkModifiers
        try:
            modifiers_url = f"{rest_host}/v3/merchants/{merchant_id}/items/{checkModifiers}/modifier_groups"
            mod_params = {}
            if locationId:
                mod_params["locationId"] = locationId
            
            async with httpx.AsyncClient(timeout=15.0) as client:
                mod_resp = await client.get(modifiers_url, headers={"Authorization": f"Bearer {access_token}"}, params=mod_params if mod_params else None)
            
            if mod_resp.status_code == 200:
                mod_data = mod_resp.json()
                modifier_groups = mod_data.get("elements") if isinstance(mod_data, dict) else (mod_data if isinstance(mod_data, list) else [])
                result_data["modifier_groups_for_item"] = modifier_groups
            else:
                result_data["modifier_groups_error"] = f"{mod_resp.status_code}: {mod_resp.text[:200]}"
            
            # Also check all modifier groups
            all_groups_url = f"{rest_host}/v3/merchants/{merchant_id}/modifier_groups"
            async with httpx.AsyncClient(timeout=15.0) as client:
                all_groups_resp = await client.get(all_groups_url, headers={"Authorization": f"Bearer {access_token}"})
            
            if all_groups_resp.status_code == 200:
                all_groups_data = all_groups_resp.json()
                all_groups = all_groups_data.get("elements") if isinstance(all_groups_data, dict) else (all_groups_data if isinstance(all_groups_data, list) else [])
                result_data["all_modifier_groups"] = all_groups if isinstance(all_groups, list) else []
            else:
                result_data["all_modifier_groups_error"] = f"{all_groups_resp.status_code}: {all_groups_resp.text[:200]}"
        except Exception as e:
            result_data["modifier_check_error"] = str(e)
    
    return result_data


@app.get("/clover/locations")
async def clover_locations(
    merchantId: Optional[str] = None,
    session: Optional[str] = None,
    x_api_key: Optional[str] = Header(None),
):
    """
    Return Clover's native locations for a merchant.
    These are the actual physical locations configured in Clover.
    
    Note: Clover API might use different endpoints:
    - /v3/merchants/{merchantId}/locations (most common)
    - /v3/locations (if merchant context is in token)
    """
    merchant_id = _resolve_merchant_id_for_browser_or_api(merchantId, session, x_api_key)
    install = await _refresh_access_token_if_needed(merchant_id)
    rest_host = install.get("restHost") or _clover_rest_host(
        install.get("region") or CLOVER_REGION, install.get("env") or CLOVER_ENV
    )
    access_token = str(install.get("accessToken"))

    # Try the standard Clover locations endpoint
    url = f"{rest_host}/v3/merchants/{merchant_id}/locations"
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(url, headers={"Authorization": f"Bearer {access_token}"})
    
    # If 404, try alternative endpoint without merchantId in path
    if resp.status_code == 404:
        alt_url = f"{rest_host}/v3/locations"
        async with httpx.AsyncClient(timeout=15.0) as client:
            alt_resp = await client.get(alt_url, headers={"Authorization": f"Bearer {access_token}"})
        if alt_resp.status_code == 200:
            data = alt_resp.json()
            if isinstance(data, list):
                return {"elements": data}
            return data
        # If both fail, return empty list (merchant might not have locations configured)
        return {"elements": []}
    
    if resp.status_code >= 400:
        # Return more detailed error for debugging
        error_text = resp.text
        try:
            error_json = resp.json()
            error_detail = error_json.get("message") or error_json.get("error") or error_text
        except:
            error_detail = error_text
        raise HTTPException(
            status_code=502, 
            detail=f"Clover API error ({resp.status_code}): {error_detail}"
        )
    
    data = resp.json()
    # Ensure we return consistent format
    if isinstance(data, list):
        return {"elements": data}
    # Clover typically returns { elements: [...] } format
    if isinstance(data, dict) and "elements" in data:
        return data
    # Wrap single object or other formats
    return {"elements": [data] if data else []}


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


@app.get("/clover/items/{item_id}/modifiers")
async def clover_item_modifiers(
    item_id: str,
    merchantId: Optional[str] = Query(None),
    session: Optional[str] = Query(None),
    locationId: Optional[str] = Query(None),
    x_api_key: Optional[str] = Header(None),
):
    """
    Return modifiers for a specific Clover item.
    Items can have modifierGroups, and each group contains modifiers.
    Modifiers might be location-specific, so locationId can be provided.
    """
    try:
        merchant_id = _resolve_merchant_id_for_browser_or_api(merchantId, session, x_api_key)
        install = await _refresh_access_token_if_needed(merchant_id)
        rest_host = install.get("restHost") or _clover_rest_host(
            install.get("region") or CLOVER_REGION, install.get("env") or CLOVER_ENV
        )
        access_token = str(install.get("accessToken"))

        result = []
        debug_info = {"strategies_tried": [], "errors": [], "item_keys": [], "modifier_groups_found": [], "item_has_modifier_groups": False, "summary": {}}
        modifier_groups = []  # Initialize to avoid NameError
        item_modifier_group_ids = []  # Initialize to avoid NameError
        
        # First, fetch the item to check if it has modifierGroups assigned
        # Try multiple variations to find modifier groups
        
        # Strategy 0a: Try fetching item with expand parameter
        item_url_base = f"{rest_host}/v3/merchants/{merchant_id}/items/{item_id}"
        expand_variations = [
            ("expand=modifierGroups", "expand_modifierGroups"),
            ("expand=modifier_groups", "expand_modifier_groups"),
            ("expand=modifiers", "expand_modifiers"),
            ("expand=modifierGroups,modifiers", "expand_both"),
            ("", "no_expand"),  # Try without expand as baseline
        ]
        
        item_data = None
        item_resp = None
        for expand_param, strategy_name in expand_variations:
            item_url = f"{item_url_base}?{expand_param}" if expand_param else item_url_base
            debug_info["strategies_tried"].append(f"fetch_item_{strategy_name}")
            try:
                async with httpx.AsyncClient(timeout=15.0) as client:
                    item_resp = await client.get(item_url, headers={"Authorization": f"Bearer {access_token}"})
                
                if item_resp.status_code == 200:
                    item_data = item_resp.json()
                    debug_info[f"item_fetch_{strategy_name}_status"] = "success"
                    debug_info[f"item_fetch_{strategy_name}_keys"] = list(item_data.keys()) if isinstance(item_data, dict) else []
                    
                    # Check for modifier groups in various field names
                    item_modifier_groups = (
                        item_data.get("modifierGroups") 
                        or item_data.get("modifier_groups")
                        or item_data.get("modifiers")
                        or item_data.get("modifierGroupsList")
                        or []
                    )
                    
                    if item_modifier_groups and isinstance(item_modifier_groups, list) and len(item_modifier_groups) > 0:
                        debug_info["item_has_modifier_groups"] = True
                        debug_info[f"item_modifier_groups_found_via_{strategy_name}"] = len(item_modifier_groups)
                        for group_ref in item_modifier_groups:
                            if isinstance(group_ref, dict) and group_ref.get("id"):
                                item_modifier_group_ids.append(group_ref.get("id"))
                            elif isinstance(group_ref, str):
                                item_modifier_group_ids.append(group_ref)
                        debug_info["item_modifier_group_ids_from_item"] = item_modifier_group_ids
                        break  # Found modifier groups, stop trying variations
                    else:
                        debug_info[f"item_fetch_{strategy_name}_modifier_groups"] = "not_found"
                else:
                    debug_info[f"item_fetch_{strategy_name}_status"] = f"failed_{item_resp.status_code}"
            except Exception as e:
                debug_info[f"item_fetch_{strategy_name}_error"] = str(e)
        
        # If we didn't get item_data yet, try one more time without expand
        if item_data is None:
            debug_info["strategies_tried"].append("fetch_item_fallback")
            async with httpx.AsyncClient(timeout=15.0) as client:
                item_resp = await client.get(item_url_base, headers={"Authorization": f"Bearer {access_token}"})
        
        # Item fetch is now handled above in the expand variations loop
        # Set item_fetch_status based on whether we got item_data
        if item_data:
            debug_info["item_fetch_status"] = "success"
            debug_info["item_keys"] = list(item_data.keys()) if isinstance(item_data, dict) else []
            if not item_modifier_group_ids:
                debug_info["item_has_modifier_groups"] = False
                debug_info["item_modifier_groups_found"] = 0
                debug_info["item_fetch_failure_reason"] = "Item fetched successfully but no modifierGroups or modifier_groups field found in item structure (tried multiple expand variations)"
                if isinstance(item_data, dict):
                    debug_info["item_available_fields"] = list(item_data.keys())
        elif item_resp:
            debug_info["item_fetch_status"] = "failed"
            debug_info["item_fetch_failure_reason"] = f"Failed to fetch item: {item_resp.status_code} - {item_resp.text[:200]}"
        else:
            debug_info["item_fetch_status"] = "failed"
            debug_info["item_fetch_failure_reason"] = "All item fetch variations failed"
        
        # Strategy 1: Try multiple variations of item-specific modifier groups endpoint
        endpoint_variations = [
            (f"{rest_host}/v3/merchants/{merchant_id}/items/{item_id}/modifier_groups", "modifier_groups", {}),
            (f"{rest_host}/v3/merchants/{merchant_id}/items/{item_id}/modifiers", "modifiers", {}),
            (f"{rest_host}/v3/merchants/{merchant_id}/items/{item_id}/modifierGroups", "modifierGroups", {}),
            (f"{rest_host}/v3/merchants/{merchant_id}/items/{item_id}/modifier-groups", "modifier-groups", {}),
        ]
        
        # Add location-specific variations if locationId is provided
        if locationId:
            for base_url, suffix, _ in endpoint_variations[:]:
                endpoint_variations.append((base_url, f"{suffix}_with_location", {"locationId": locationId}))
        
        for url, variation_name, params in endpoint_variations:
            debug_info["strategies_tried"].append(f"items/{item_id}/{variation_name}")
            try:
                async with httpx.AsyncClient(timeout=15.0) as client:
                    resp = await client.get(url, headers={"Authorization": f"Bearer {access_token}"}, params=params if params else None)
                
                debug_info[f"strategy1_{variation_name}_status"] = resp.status_code
                
                if resp.status_code == 200:
                    modifier_groups_data = resp.json()
                    modifier_groups = modifier_groups_data.get("elements") if isinstance(modifier_groups_data, dict) else (modifier_groups_data if isinstance(modifier_groups_data, list) else [])
                    debug_info["modifier_groups_found"] = [g.get("id") if isinstance(g, dict) else str(g) for g in modifier_groups] if modifier_groups else []
                    debug_info[f"strategy1_{variation_name}_success"] = True
                    debug_info[f"strategy1_{variation_name}_groups_count"] = len(modifier_groups) if isinstance(modifier_groups, list) else 0
                    
                    if modifier_groups:
                        item_modifier_group_ids = [g.get("id") for g in modifier_groups if isinstance(g, dict) and g.get("id")]
                        debug_info["item_has_modifier_groups"] = True
                        break  # Found groups, stop trying variations
                elif resp.status_code == 404:
                    debug_info[f"strategy1_{variation_name}_failure"] = "404_not_found"
                elif resp.status_code == 405:
                    debug_info[f"strategy1_{variation_name}_failure"] = "405_method_not_allowed"
                else:
                    debug_info[f"strategy1_{variation_name}_failure"] = f"{resp.status_code}_{resp.text[:50]}"
            except Exception as e:
                debug_info[f"strategy1_{variation_name}_error"] = str(e)
        
        # If we still don't have modifier_groups, try POST method (some APIs use POST for relationships)
        if not modifier_groups:
            debug_info["strategies_tried"].append("items_modifier_groups_POST")
            try:
                url = f"{rest_host}/v3/merchants/{merchant_id}/items/{item_id}/modifier_groups"
                async with httpx.AsyncClient(timeout=15.0) as client:
                    resp = await client.post(url, headers={"Authorization": f"Bearer {access_token}"}, json={})
                debug_info["strategy1_POST_status"] = resp.status_code
                if resp.status_code == 200:
                    modifier_groups_data = resp.json()
                    modifier_groups = modifier_groups_data.get("elements") if isinstance(modifier_groups_data, dict) else (modifier_groups_data if isinstance(modifier_groups_data, list) else [])
                    if modifier_groups:
                        item_modifier_group_ids = [g.get("id") for g in modifier_groups if isinstance(g, dict) and g.get("id")]
                        debug_info["item_has_modifier_groups"] = True
            except Exception as e:
                debug_info["strategy1_POST_error"] = str(e)
        
        # Strategy 1 results summary
        if modifier_groups:
            debug_info["strategy1_status"] = "success"
            debug_info["strategy1_groups_count"] = len(modifier_groups)
        else:
            debug_info["strategy1_status"] = "failed"
            debug_info["strategy1_failure_reason"] = "All endpoint variations failed - no modifier groups found via item-specific endpoints"
        
        # Now fetch modifiers for the groups we found
        groups_to_process = modifier_groups if modifier_groups else []
        
        for group in groups_to_process:
            if not isinstance(group, dict):
                continue
            group_id = group.get("id")
            group_name = group.get("name")
            
            if not group_id:
                continue
            
            # Check if modifiers are embedded in the group
            group_modifiers = group.get("modifiers") or group.get("modifierList") or group.get("elements") or []
            if group_modifiers and isinstance(group_modifiers, list) and len(group_modifiers) > 0:
                # Modifiers are embedded in the group
                for modifier in group_modifiers:
                    if isinstance(modifier, dict):
                        modifier["modifierGroup"] = group
                        result.append(modifier)
            else:
                # Fetch modifiers separately for this group
                modifiers_url = f"{rest_host}/v3/merchants/{merchant_id}/modifier_groups/{group_id}/modifiers"
                mod_params = {}
                if locationId:
                    mod_params["locationId"] = locationId
                
                async with httpx.AsyncClient(timeout=15.0) as client:
                    modifiers_resp = await client.get(modifiers_url, headers={"Authorization": f"Bearer {access_token}"}, params=mod_params if mod_params else None)
                
                if modifiers_resp.status_code == 200:
                    modifiers_data = modifiers_resp.json()
                    modifiers = modifiers_data.get("elements") if isinstance(modifiers_data, dict) else (modifiers_data if isinstance(modifiers_data, list) else [])
                    debug_info[f"group_{group_id}_modifiers_fetched"] = len(modifiers) if isinstance(modifiers, list) else 0
                    for modifier in modifiers:
                        if isinstance(modifier, dict):
                            modifier["modifierGroup"] = group
                            result.append(modifier)
                elif modifiers_resp.status_code == 404:
                    debug_info[f"group_{group_id}_modifiers_status"] = "404_not_found"
                    debug_info[f"group_{group_id}_modifiers_failure"] = f"Modifiers endpoint returned 404 for group {group_id} ({group_name})"
                else:
                    error_text = modifiers_resp.text
                    debug_info[f"group_{group_id}_modifiers_status"] = f"error_{modifiers_resp.status_code}"
                    debug_info[f"group_{group_id}_modifiers_failure"] = f"Failed to fetch modifiers: {modifiers_resp.status_code} - {error_text[:100]}"
                    debug_info["errors"].append(f"Group {group_id} ({group_name}): {modifiers_resp.status_code} - {error_text[:100]}")
    
        # If we found modifiers, return them
        if result:
            return {"elements": result, "debug": debug_info}
        
        # Strategy 2: Fetch item first to check if it has modifierGroups, then fetch those specific groups
        # This is more reliable than Strategy 1 in some Clover setups
        item_url = f"{rest_host}/v3/merchants/{merchant_id}/items/{item_id}"
        debug_info["strategies_tried"].append("fetch_item_then_groups")
        
        item_modifier_group_ids = []
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                item_resp = await client.get(item_url, headers={"Authorization": f"Bearer {access_token}"})
            
            if item_resp.status_code == 200:
                item_data = item_resp.json()
                debug_info["item_keys"] = list(item_data.keys()) if isinstance(item_data, dict) else []
                
                # Check if item has modifierGroups embedded
                item_modifier_groups = item_data.get("modifierGroups") or item_data.get("modifier_groups") or []
                if item_modifier_groups and isinstance(item_modifier_groups, list):
                    for group_ref in item_modifier_groups:
                        if isinstance(group_ref, dict) and group_ref.get("id"):
                            item_modifier_group_ids.append(group_ref.get("id"))
                        elif isinstance(group_ref, str):
                            item_modifier_group_ids.append(group_ref)
                
                debug_info["item_modifier_group_ids_from_item"] = item_modifier_group_ids
                
                # If we found modifier group IDs from the item, fetch modifiers for those specific groups
                if item_modifier_group_ids:
                    for group_id in item_modifier_group_ids:
                        modifiers_url = f"{rest_host}/v3/merchants/{merchant_id}/modifier_groups/{group_id}/modifiers"
                        mod_params = {}
                        if locationId:
                            mod_params["locationId"] = locationId
                        
                        try:
                            async with httpx.AsyncClient(timeout=15.0) as client:
                                modifiers_resp = await client.get(modifiers_url, headers={"Authorization": f"Bearer {access_token}"}, params=mod_params if mod_params else None)
                            
                            if modifiers_resp.status_code == 200:
                                modifiers_data = modifiers_resp.json()
                                modifiers = modifiers_data.get("elements") if isinstance(modifiers_data, dict) else (modifiers_data if isinstance(modifiers_data, list) else [])
                                # Find the group info to attach to modifiers
                                all_groups_url = f"{rest_host}/v3/merchants/{merchant_id}/modifier_groups"
                                async with httpx.AsyncClient(timeout=15.0) as client:
                                    groups_resp = await client.get(all_groups_url, headers={"Authorization": f"Bearer {access_token}"})
                                group_info = {}
                                if groups_resp.status_code == 200:
                                    groups_data = groups_resp.json()
                                    all_groups = groups_data.get("elements") if isinstance(groups_data, dict) else (groups_data if isinstance(groups_data, list) else [])
                                    for g in all_groups if isinstance(all_groups, list) else []:
                                        if isinstance(g, dict) and g.get("id") == group_id:
                                            group_info = g
                                            break
                                
                                for modifier in modifiers:
                                    if isinstance(modifier, dict):
                                        modifier["modifierGroup"] = group_info if group_info else {"id": group_id}
                                        result.append(modifier)
                        except Exception as e:
                            debug_info["errors"].append(f"Error fetching modifiers for group {group_id}: {str(e)}")
        except Exception as e:
            debug_info["errors"].append(f"Exception fetching item: {str(e)}")
        
        item_group_id = None
        if isinstance(item_data, dict):
            item_group = item_data.get("itemGroup") if isinstance(item_data.get("itemGroup"), dict) else {}
            item_group_id = item_group.get("id")

        # Strategy 2a: Derive modifiers through Clover itemGroup -> modifier_groups relation
        # This is an automatic workaround that does not require manual mappings.
        if not result and isinstance(item_data, dict):
            if item_group_id:
                debug_info["strategies_tried"].append("fetch_item_group_modifier_groups")
                item_group_groups_url = f"{rest_host}/v3/merchants/{merchant_id}/item_groups/{item_group_id}/modifier_groups"
                try:
                    async with httpx.AsyncClient(timeout=15.0) as client:
                        item_group_groups_resp = await client.get(
                            item_group_groups_url,
                            headers={"Authorization": f"Bearer {access_token}"},
                        )
                    debug_info["item_group_modifier_groups_status"] = item_group_groups_resp.status_code
                    if item_group_groups_resp.status_code == 200:
                        item_group_groups_data = item_group_groups_resp.json()
                        item_group_groups = (
                            item_group_groups_data.get("elements")
                            if isinstance(item_group_groups_data, dict)
                            else (item_group_groups_data if isinstance(item_group_groups_data, list) else [])
                        )
                        debug_info["item_group_modifier_groups_found"] = len(item_group_groups) if isinstance(item_group_groups, list) else 0
                        for group in item_group_groups if isinstance(item_group_groups, list) else []:
                            if not isinstance(group, dict):
                                continue
                            group_id = group.get("id")
                            if not group_id:
                                continue
                            modifiers_url = f"{rest_host}/v3/merchants/{merchant_id}/modifier_groups/{group_id}/modifiers"
                            mod_params = {}
                            if locationId:
                                mod_params["locationId"] = locationId
                            try:
                                async with httpx.AsyncClient(timeout=15.0) as client:
                                    modifiers_resp = await client.get(
                                        modifiers_url,
                                        headers={"Authorization": f"Bearer {access_token}"},
                                        params=mod_params if mod_params else None,
                                    )
                                if modifiers_resp.status_code == 200:
                                    modifiers_data = modifiers_resp.json()
                                    modifiers = (
                                        modifiers_data.get("elements")
                                        if isinstance(modifiers_data, dict)
                                        else (modifiers_data if isinstance(modifiers_data, list) else [])
                                    )
                                    for modifier in modifiers:
                                        if isinstance(modifier, dict):
                                            modifier["modifierGroup"] = group
                                            result.append(modifier)
                            except Exception as e:
                                debug_info["errors"].append(
                                    f"Error fetching modifiers for itemGroup group {group_id}: {str(e)}"
                                )
                    else:
                        debug_info["item_group_modifier_groups_failure"] = item_group_groups_resp.text[:120]
                except Exception as e:
                    debug_info["errors"].append(f"Exception fetching itemGroup modifier groups: {str(e)}")
            else:
                debug_info["item_group_id_missing"] = True

        # Strategy 2aa: Reverse-lookup by modifier group details (expand=items,itemGroups)
        # Some Clover setups only expose relationships on group detail payloads.
        if not result:
            debug_info["strategies_tried"].append("reverse_lookup_group_details")
            matched_groups = []
            try:
                all_groups_url = f"{rest_host}/v3/merchants/{merchant_id}/modifier_groups"
                async with httpx.AsyncClient(timeout=15.0) as client:
                    groups_resp = await client.get(all_groups_url, headers={"Authorization": f"Bearer {access_token}"})

                if groups_resp.status_code == 200:
                    groups_data = groups_resp.json()
                    all_groups = groups_data.get("elements") if isinstance(groups_data, dict) else (groups_data if isinstance(groups_data, list) else [])
                    for group in all_groups if isinstance(all_groups, list) else []:
                        if not isinstance(group, dict):
                            continue
                        group_id = group.get("id")
                        if not group_id:
                            continue

                        detail_urls = [
                            f"{rest_host}/v3/merchants/{merchant_id}/modifier_groups/{group_id}?expand=items,itemGroups",
                            f"{rest_host}/v3/merchants/{merchant_id}/modifier_groups/{group_id}?expand=items",
                            f"{rest_host}/v3/merchants/{merchant_id}/modifier_groups/{group_id}?expand=itemGroups",
                        ]
                        matched = False
                        matched_group_payload = group
                        for detail_url in detail_urls:
                            try:
                                async with httpx.AsyncClient(timeout=15.0) as client:
                                    detail_resp = await client.get(detail_url, headers={"Authorization": f"Bearer {access_token}"})
                                if detail_resp.status_code != 200:
                                    continue
                                detail = detail_resp.json()
                                if isinstance(detail, dict):
                                    matched_group_payload = detail

                                # items refs may be list or {"elements":[...]}
                                items_refs = detail.get("items") if isinstance(detail, dict) else []
                                if isinstance(items_refs, dict):
                                    items_refs = items_refs.get("elements") or []
                                item_ids = []
                                for ref in items_refs if isinstance(items_refs, list) else []:
                                    if isinstance(ref, dict) and ref.get("id"):
                                        item_ids.append(ref.get("id"))
                                    elif isinstance(ref, str):
                                        item_ids.append(ref)
                                if item_id in item_ids:
                                    matched = True

                                # itemGroups refs may be list or {"elements":[...]}
                                if not matched and item_group_id:
                                    item_groups_refs = detail.get("itemGroups") or detail.get("item_groups") if isinstance(detail, dict) else []
                                    if isinstance(item_groups_refs, dict):
                                        item_groups_refs = item_groups_refs.get("elements") or []
                                    item_group_ids = []
                                    for ref in item_groups_refs if isinstance(item_groups_refs, list) else []:
                                        if isinstance(ref, dict) and ref.get("id"):
                                            item_group_ids.append(ref.get("id"))
                                        elif isinstance(ref, str):
                                            item_group_ids.append(ref)
                                    if item_group_id in item_group_ids:
                                        matched = True

                                if matched:
                                    break
                            except Exception:
                                continue

                        if matched:
                            matched_groups.append(matched_group_payload)

                    debug_info["reverse_lookup_group_details_matched_groups"] = len(matched_groups)
                    for group in matched_groups:
                        group_id = group.get("id") if isinstance(group, dict) else None
                        if not group_id:
                            continue
                        modifiers_url = f"{rest_host}/v3/merchants/{merchant_id}/modifier_groups/{group_id}/modifiers"
                        mod_params = {}
                        if locationId:
                            mod_params["locationId"] = locationId
                        try:
                            async with httpx.AsyncClient(timeout=15.0) as client:
                                modifiers_resp = await client.get(
                                    modifiers_url,
                                    headers={"Authorization": f"Bearer {access_token}"},
                                    params=mod_params if mod_params else None,
                                )
                            if modifiers_resp.status_code == 200:
                                modifiers_data = modifiers_resp.json()
                                modifiers = modifiers_data.get("elements") if isinstance(modifiers_data, dict) else (modifiers_data if isinstance(modifiers_data, list) else [])
                                for modifier in modifiers:
                                    if isinstance(modifier, dict):
                                        modifier["modifierGroup"] = group
                                        result.append(modifier)
                        except Exception as e:
                            debug_info["errors"].append(f"Error fetching modifiers from reverse-lookup group {group_id}: {str(e)}")
                else:
                    debug_info["reverse_lookup_group_list_status"] = groups_resp.status_code
            except Exception as e:
                debug_info["errors"].append(f"Exception in reverse lookup strategy: {str(e)}")

        # Strategy 2b: If Strategy 1 found groups but no modifiers yet, try fetching modifiers for those groups
        # modifier_groups is initialized at the start, so we can use it directly
        if not result and modifier_groups:
            debug_info["strategies_tried"].append("fetch_modifiers_for_strategy1_groups")
            for group in modifier_groups:
                if not isinstance(group, dict):
                    continue
                group_id = group.get("id")
                if not group_id:
                    continue
                
                modifiers_url = f"{rest_host}/v3/merchants/{merchant_id}/modifier_groups/{group_id}/modifiers"
                mod_params = {}
                if locationId:
                    mod_params["locationId"] = locationId
                
                try:
                    async with httpx.AsyncClient(timeout=15.0) as client:
                        modifiers_resp = await client.get(modifiers_url, headers={"Authorization": f"Bearer {access_token}"}, params=mod_params if mod_params else None)
                    
                    if modifiers_resp.status_code == 200:
                        modifiers_data = modifiers_resp.json()
                        modifiers = modifiers_data.get("elements") if isinstance(modifiers_data, dict) else (modifiers_data if isinstance(modifiers_data, list) else [])
                        for modifier in modifiers:
                            if isinstance(modifier, dict):
                                modifier["modifierGroup"] = group
                                result.append(modifier)
                except Exception as e:
                    debug_info["errors"].append(f"Error fetching modifiers for group {group_id}: {str(e)}")
        
        # Strategy 2c: Fallback - Only return modifiers if we have evidence the item might have them
        # The 405 error shows that /items/{item_id}/modifier_groups endpoint doesn't exist or doesn't support GET
        # Since we can't verify item->modifier relationship via API, we'll be conservative:
        # Only return all modifiers if the item structure suggests it might have modifiers
        # Otherwise, return empty to avoid showing modifiers for items that don't have them
        if not result or len(result) == 0:
            # Check if we have ANY evidence the item has modifier groups
            has_evidence_of_modifiers = (
                item_modifier_group_ids  # Found modifierGroups in item structure
                or modifier_groups  # Found groups via Strategy 1 (even if modifiers couldn't be fetched)
                or debug_info.get("item_has_modifier_groups", False)  # Explicitly marked as having groups
            )
            
            debug_info["has_evidence_of_modifiers"] = has_evidence_of_modifiers
            
            # WORKAROUND: Since Clover's API doesn't expose item->modifier relationships,
            # we'll use a more permissive fallback: if we can't find evidence, but modifier groups exist,
            # we'll check if this is a known item that should have modifiers.
            # For now, we'll be conservative and only show modifiers if we have evidence OR if it's a specific known item.
            # TODO: Consider storing item->modifier mappings in DynamoDB as a workaround
            
            # Only use fallback if we have evidence the item might have modifiers
            # Otherwise, return empty to avoid showing modifiers for items that don't have them
            if has_evidence_of_modifiers:
                # Since Clover's API doesn't expose item->modifier relationships (405 error, no modifierGroups field),
                # we can't verify which items have modifiers. As a compromise, we'll return all modifiers
                # but note this limitation. This ensures modifiers show up for items that have them.
                # Note: This means items without modifiers might also show modifiers, but that's a Clover API limitation.
                debug_info["fallback_compromise"] = True
                debug_info["fallback_reason"] = "Clover API doesn't expose item->modifier relationship (405 on item-specific endpoint, no modifierGroups in item structure). Using fallback to return all modifiers."
                if "summary" not in debug_info:
                    debug_info["summary"] = {}
                debug_info["summary"]["why_no_modifiers"] = "Clover API limitation: Cannot verify item-specific modifier assignment via API. Returning all modifiers as fallback."
                
                # We have some evidence - proceed with fallback but only for groups we found
                debug_info["fallback_evidence_found"] = True
                debug_info["strategies_tried"].append("fallback_all_groups")
                debug_info["fallback_triggered"] = True
                all_groups_url = f"{rest_host}/v3/merchants/{merchant_id}/modifier_groups"
                try:
                    async with httpx.AsyncClient(timeout=15.0) as client:
                        all_groups_resp = await client.get(all_groups_url, headers={"Authorization": f"Bearer {access_token}"})
                    
                    debug_info["all_groups_status"] = all_groups_resp.status_code
                    debug_info["all_groups_url_called"] = all_groups_url
                    
                    if all_groups_resp.status_code == 200:
                        all_groups_data = all_groups_resp.json()
                        all_groups = all_groups_data.get("elements") if isinstance(all_groups_data, dict) else (all_groups_data if isinstance(all_groups_data, list) else [])
                        debug_info["total_groups_found"] = len(all_groups) if isinstance(all_groups, list) else 0
                        debug_info["group_names"] = [g.get("name") for g in all_groups if isinstance(g, dict) and g.get("name")]
                        debug_info["group_ids"] = [g.get("id") for g in all_groups if isinstance(g, dict) and g.get("id")]
                        
                        # Fetch modifiers for ALL groups as fallback
                        modifiers_fetched_count = 0
                        for group in all_groups if isinstance(all_groups, list) else []:
                            if not isinstance(group, dict):
                                continue
                            group_id = group.get("id")
                            if not group_id:
                                continue
                            
                            modifiers_url = f"{rest_host}/v3/merchants/{merchant_id}/modifier_groups/{group_id}/modifiers"
                            mod_params = {}
                            if locationId:
                                mod_params["locationId"] = locationId
                            
                            try:
                                async with httpx.AsyncClient(timeout=15.0) as client:
                                    modifiers_resp = await client.get(modifiers_url, headers={"Authorization": f"Bearer {access_token}"}, params=mod_params if mod_params else None)
                                
                                debug_info[f"group_{group_id}_modifiers_status"] = modifiers_resp.status_code
                                
                                if modifiers_resp.status_code == 200:
                                    modifiers_data = modifiers_resp.json()
                                    modifiers = modifiers_data.get("elements") if isinstance(modifiers_data, dict) else (modifiers_data if isinstance(modifiers_data, list) else [])
                                    for modifier in modifiers:
                                        if isinstance(modifier, dict):
                                            modifier["modifierGroup"] = group
                                            result.append(modifier)
                                            modifiers_fetched_count += 1
                                else:
                                    debug_info["errors"].append(f"Group {group_id} modifiers returned {modifiers_resp.status_code}: {modifiers_resp.text[:100]}")
                            except Exception as e:
                                debug_info["errors"].append(f"Error fetching modifiers for group {group_id}: {str(e)}")
                        
                        debug_info["modifiers_fetched_in_fallback"] = modifiers_fetched_count
                    else:
                        debug_info["errors"].append(f"Failed to fetch all groups: {all_groups_resp.status_code} - {all_groups_resp.text[:200]}")
                except Exception as e:
                    debug_info["errors"].append(f"Exception fetching all groups: {str(e)}")
                    import traceback
                    debug_info["exception_traceback"] = traceback.format_exc()
            else:
                # No evidence of modifiers - return empty
                debug_info["fallback_skipped"] = True
                debug_info["fallback_skipped_reason"] = "No evidence found that this item has modifier groups assigned. Returning empty modifiers to avoid showing modifiers for items without them."
                if "summary" not in debug_info:
                    debug_info["summary"] = {}
                debug_info["summary"]["why_no_modifiers"] = "No evidence found that this item has modifier groups. Item structure doesn't contain modifierGroups field, and no item-specific modifier groups were found via API."
        
        # Strategy 3: Fetch item to check its structure and see if it has modifierGroups embedded
        item_url = f"{rest_host}/v3/merchants/{merchant_id}/items/{item_id}"
        debug_info["strategies_tried"].append("fetch_item_structure")
        async with httpx.AsyncClient(timeout=15.0) as client:
            item_resp = await client.get(item_url, headers={"Authorization": f"Bearer {access_token}"})
        
        if item_resp.status_code == 200:
            item_data = item_resp.json()
            debug_info["item_keys"] = list(item_data.keys()) if isinstance(item_data, dict) else []
            
            # Check if item has modifierGroups embedded
            item_modifier_groups = item_data.get("modifierGroups") or item_data.get("modifier_groups") or []
            if item_modifier_groups and isinstance(item_modifier_groups, list) and len(item_modifier_groups) > 0:
                debug_info["item_has_modifier_groups"] = True
                debug_info["item_modifier_group_ids"] = [g.get("id") if isinstance(g, dict) else str(g) for g in item_modifier_groups]
                
                # Fetch modifiers for these specific groups
                for group_ref in item_modifier_groups:
                    if not isinstance(group_ref, dict):
                        continue
                    group_id = group_ref.get("id")
                    if not group_id:
                        continue
                    
                    # Fetch modifiers for this group
                    modifiers_url = f"{rest_host}/v3/merchants/{merchant_id}/modifier_groups/{group_id}/modifiers"
                    mod_params = {}
                    if locationId:
                        mod_params["locationId"] = locationId
                    
                    try:
                        async with httpx.AsyncClient(timeout=15.0) as client:
                            modifiers_resp = await client.get(modifiers_url, headers={"Authorization": f"Bearer {access_token}"}, params=mod_params if mod_params else None)
                        
                        if modifiers_resp.status_code == 200:
                            modifiers_data = modifiers_resp.json()
                            modifiers = modifiers_data.get("elements") if isinstance(modifiers_data, dict) else (modifiers_data if isinstance(modifiers_data, list) else [])
                            for modifier in modifiers:
                                if isinstance(modifier, dict):
                                    modifier["modifierGroup"] = group_ref
                                    result.append(modifier)
                    except Exception as e:
                        debug_info["errors"].append(f"Error fetching modifiers for group {group_id}: {str(e)}")
            else:
                debug_info["item_has_modifier_groups"] = False
        
        # Summary of what happened
        debug_info["summary"] = {
            "item_has_modifier_groups": debug_info.get("item_has_modifier_groups", False),
            "item_modifier_group_ids": item_modifier_group_ids,
            "modifier_groups_found_via_strategy1": len(modifier_groups) if modifier_groups else 0,
            "total_modifiers_found": len(result),
            "strategies_that_ran": debug_info.get("strategies_tried", []),
            "fallback_was_used": debug_info.get("fallback_triggered", False),
            "why_no_modifiers": (
                "Item has no modifier groups assigned" if not debug_info.get("item_has_modifier_groups", False) and not modifier_groups
                else "Modifier groups found but modifiers couldn't be fetched" if (modifier_groups or item_modifier_group_ids) and not result
                else "All strategies failed - fallback returned all modifiers" if debug_info.get("fallback_triggered", False)
                else "Modifiers found successfully"
            )
        }
        
        return {"elements": result, "debug": debug_info}
    except Exception as e:
        import traceback
        error_traceback = traceback.format_exc()
        return {
            "elements": [],
            "debug": {
                "error": str(e),
                "error_type": type(e).__name__,
                "traceback": error_traceback,
                "item_id": item_id,
                "merchantId": merchantId,
                "locationId": locationId
            }
        }


@app.get("/clover/debug/item-modifier-relationships")
async def clover_item_modifier_relationships(
    merchantId: Optional[str] = Query(None),
    session: Optional[str] = Query(None),
    locationId: Optional[str] = Query(None),
    x_api_key: Optional[str] = Header(None),
):
    """
    Debug endpoint: Shows which items are connected to which modifiers.
    Returns a clear mapping of item -> modifier groups -> modifiers.
    """
    try:
        merchant_id = _resolve_merchant_id_for_browser_or_api(merchantId, session, x_api_key)
        install = await _refresh_access_token_if_needed(merchant_id)
        rest_host = install.get("restHost") or _clover_rest_host(
            install.get("region") or CLOVER_REGION, install.get("env") or CLOVER_ENV
        )
        access_token = str(install.get("accessToken"))
        
        # Fetch all items
        items_url = f"{rest_host}/v3/merchants/{merchant_id}/items"
        items_params = {"limit": 100}
        if locationId:
            items_params["locationId"] = locationId
        
        async with httpx.AsyncClient(timeout=15.0) as client:
            items_resp = await client.get(items_url, headers={"Authorization": f"Bearer {access_token}"}, params=items_params)
        
        if items_resp.status_code != 200:
            return {
                "error": f"Failed to fetch items: {items_resp.status_code}",
                "response": items_resp.text[:500]
            }
        
        items_data = items_resp.json()
        items = items_data.get("elements") if isinstance(items_data, dict) else (items_data if isinstance(items_data, list) else [])
        
        # Fetch all modifier groups
        groups_url = f"{rest_host}/v3/merchants/{merchant_id}/modifier_groups"
        async with httpx.AsyncClient(timeout=15.0) as client:
            groups_resp = await client.get(groups_url, headers={"Authorization": f"Bearer {access_token}"})
        
        all_modifier_groups = {}
        if groups_resp.status_code == 200:
            groups_data = groups_resp.json()
            groups = groups_data.get("elements") if isinstance(groups_data, dict) else (groups_data if isinstance(groups_data, list) else [])
            for group in groups if isinstance(groups, list) else []:
                if isinstance(group, dict) and group.get("id"):
                    all_modifier_groups[group.get("id")] = group
        
        # Build relationships
        relationships = []
        items_with_modifiers = 0
        items_without_modifiers = 0
        
        for item in items if isinstance(items, list) else []:
            if not isinstance(item, dict):
                continue
            
            item_id = item.get("id")
            item_name = item.get("name", "Unknown")
            
            # Try to find modifier groups for this item
            item_modifier_groups = []
            debug_strategies_tried = []
            
            # Strategy 1: Check if item has modifierGroups field directly
            modifier_group_refs = item.get("modifierGroups") or item.get("modifier_groups") or []
            if modifier_group_refs and isinstance(modifier_group_refs, list):
                debug_strategies_tried.append("strategy1_direct_field")
                for group_ref in modifier_group_refs:
                    group_id = group_ref.get("id") if isinstance(group_ref, dict) else (group_ref if isinstance(group_ref, str) else None)
                    if group_id and group_id in all_modifier_groups:
                        item_modifier_groups.append(all_modifier_groups[group_id])
            
            # Strategy 2: Try fetching item with various expand parameters
            if not item_modifier_groups:
                expand_variations = [
                    "expand=modifierGroups",
                    "expand=modifier_groups",
                    "expand=modifiers",
                    "expand=modifierGroups,modifiers"
                ]
                for expand_param in expand_variations:
                    try:
                        item_url = f"{rest_host}/v3/merchants/{merchant_id}/items/{item_id}?{expand_param}"
                        async with httpx.AsyncClient(timeout=10.0) as client:
                            item_detail_resp = await client.get(item_url, headers={"Authorization": f"Bearer {access_token}"})
                        if item_detail_resp.status_code == 200:
                            item_detail = item_detail_resp.json()
                            modifier_group_refs = item_detail.get("modifierGroups") or item_detail.get("modifier_groups") or []
                            if modifier_group_refs and isinstance(modifier_group_refs, list):
                                debug_strategies_tried.append(f"strategy2_expand_{expand_param}")
                                for group_ref in modifier_group_refs:
                                    group_id = group_ref.get("id") if isinstance(group_ref, dict) else (group_ref if isinstance(group_ref, str) else None)
                                    if group_id and group_id in all_modifier_groups:
                                        item_modifier_groups.append(all_modifier_groups[group_id])
                                        break  # Found groups, stop trying variations
                    except:
                        pass
            
            # Strategy 3: Try item-specific modifier groups endpoint
            if not item_modifier_groups:
                endpoint_variations = [
                    f"{rest_host}/v3/merchants/{merchant_id}/items/{item_id}/modifier_groups",
                    f"{rest_host}/v3/merchants/{merchant_id}/items/{item_id}/modifiers",
                    f"{rest_host}/v3/merchants/{merchant_id}/items/{item_id}/modifierGroups"
                ]
                for endpoint_url in endpoint_variations:
                    try:
                        async with httpx.AsyncClient(timeout=10.0) as client:
                            endpoint_resp = await client.get(endpoint_url, headers={"Authorization": f"Bearer {access_token}"})
                        if endpoint_resp.status_code == 200:
                            endpoint_data = endpoint_resp.json()
                            groups_from_endpoint = endpoint_data.get("elements") if isinstance(endpoint_data, dict) else (endpoint_data if isinstance(endpoint_data, list) else [])
                            if groups_from_endpoint:
                                debug_strategies_tried.append(f"strategy3_endpoint_{endpoint_url.split('/')[-1]}")
                                for group_ref in groups_from_endpoint if isinstance(groups_from_endpoint, list) else []:
                                    group_id = group_ref.get("id") if isinstance(group_ref, dict) else (group_ref if isinstance(group_ref, str) else None)
                                    if group_id and group_id in all_modifier_groups:
                                        item_modifier_groups.append(all_modifier_groups[group_id])
                                        break  # Found groups, stop trying variations
                    except:
                        pass
            
            # Strategy 4: Check modifier groups for item associations (reverse lookup)
            if not item_modifier_groups:
                for group_id, group in all_modifier_groups.items():
                    # Check if group has items field
                    group_items = group.get("items") or group.get("itemIds") or group.get("item_ids") or []
                    if isinstance(group_items, list) and item_id in group_items:
                        debug_strategies_tried.append("strategy4_reverse_lookup_items_field")
                        item_modifier_groups.append(group)
                    # Check if group has itemGroups field
                    group_item_groups = group.get("itemGroups") or group.get("item_groups") or []
                    if isinstance(group_item_groups, list):
                        # Check if this item belongs to any of those item groups
                        item_group_id = item.get("itemGroup", {}).get("id") if isinstance(item.get("itemGroup"), dict) else None
                        if item_group_id:
                            for ref in group_item_groups:
                                ref_id = ref.get("id") if isinstance(ref, dict) else (ref if isinstance(ref, str) else None)
                                if ref_id == item_group_id:
                                    debug_strategies_tried.append("strategy4_reverse_lookup_itemGroups")
                                    item_modifier_groups.append(group)
                                    break
            
            # Fetch modifiers for each group
            modifier_details = []
            for group in item_modifier_groups:
                group_id = group.get("id")
                group_name = group.get("name", "Unknown")
                
                # Fetch modifiers for this group
                modifiers_url = f"{rest_host}/v3/merchants/{merchant_id}/modifier_groups/{group_id}/modifiers"
                mod_params = {}
                if locationId:
                    mod_params["locationId"] = locationId
                
                try:
                    async with httpx.AsyncClient(timeout=10.0) as client:
                        modifiers_resp = await client.get(modifiers_url, headers={"Authorization": f"Bearer {access_token}"}, params=mod_params if mod_params else None)
                    if modifiers_resp.status_code == 200:
                        modifiers_data = modifiers_resp.json()
                        modifiers = modifiers_data.get("elements") if isinstance(modifiers_data, dict) else (modifiers_data if isinstance(modifiers_data, list) else [])
                        modifier_names = [m.get("name", "Unknown") for m in modifiers if isinstance(m, dict)]
                        modifier_details.append({
                            "group_id": group_id,
                            "group_name": group_name,
                            "modifiers": modifier_names,
                            "modifier_count": len(modifiers) if isinstance(modifiers, list) else 0
                        })
                except:
                    pass
            
            if item_modifier_groups:
                items_with_modifiers += 1
            else:
                items_without_modifiers += 1
            
            relationships.append({
                "item_id": item_id,
                "item_name": item_name,
                "has_modifiers": len(item_modifier_groups) > 0,
                "modifier_groups": modifier_details,
                "modifier_group_count": len(item_modifier_groups),
                "debug": {
                    "strategies_tried": debug_strategies_tried if debug_strategies_tried else ["none_found"],
                    "item_structure_keys": list(item.keys()) if isinstance(item, dict) else [],
                    "item_has_modifierGroups_field": bool(item.get("modifierGroups") or item.get("modifier_groups"))
                }
            })
        
        # Also include modifier group details for reference
        modifier_group_details = []
        for group_id, group in all_modifier_groups.items():
            modifier_group_details.append({
                "group_id": group_id,
                "group_name": group.get("name", "Unknown"),
                "group_structure_keys": list(group.keys()) if isinstance(group, dict) else [],
                "has_items_field": bool(group.get("items") or group.get("itemIds") or group.get("item_ids")),
                "has_itemGroups_field": bool(group.get("itemGroups") or group.get("item_groups"))
            })
        
        return {
            "merchant_id": merchant_id,
            "location_id": locationId or "all",
            "summary": {
                "total_items": len(relationships),
                "items_with_modifiers": items_with_modifiers,
                "items_without_modifiers": items_without_modifiers,
                "total_modifier_groups": len(all_modifier_groups),
                "note": "Clover API doesn't expose item-modifier relationships directly. This endpoint tries multiple strategies but may not find all relationships."
            },
            "modifier_groups_available": modifier_group_details,
            "relationships": relationships
        }
    except Exception as e:
        import traceback
        return {
            "error": str(e),
            "error_type": type(e).__name__,
            "traceback": traceback.format_exc()
        }


@app.get("/clover/test-modifiers")
async def clover_test_modifiers(
    merchantId: Optional[str] = Query(None),
    session: Optional[str] = Query(None),
    x_api_key: Optional[str] = Header(None),
):
    """
    Simple test endpoint to check if modifier groups exist in Clover.
    This doesn't require an item ID - just shows all modifier groups.
    """
    merchant_id = _resolve_merchant_id_for_browser_or_api(merchantId, session, x_api_key)
    install = await _refresh_access_token_if_needed(merchant_id)
    rest_host = install.get("restHost") or _clover_rest_host(
        install.get("region") or CLOVER_REGION, install.get("env") or CLOVER_ENV
    )
    access_token = str(install.get("accessToken"))
    
    result = {
        "merchantId": merchant_id,
        "status": "checking",
        "modifier_groups": [],
        "errors": []
    }
    
    # Fetch ALL modifier groups
    try:
        all_groups_url = f"{rest_host}/v3/merchants/{merchant_id}/modifier_groups"
        async with httpx.AsyncClient(timeout=15.0) as client:
            groups_resp = await client.get(all_groups_url, headers={"Authorization": f"Bearer {access_token}"})
        
        result["clover_api_status"] = groups_resp.status_code
        result["clover_api_url"] = all_groups_url
        
        if groups_resp.status_code == 200:
            groups_data = groups_resp.json()
            groups = groups_data.get("elements") if isinstance(groups_data, dict) else (groups_data if isinstance(groups_data, list) else [])
            result["modifier_groups"] = groups if isinstance(groups, list) else []
            result["status"] = "success"
            result["total_groups"] = len(result["modifier_groups"])
        else:
            result["status"] = "error"
            result["errors"].append(f"Clover API returned {groups_resp.status_code}: {groups_resp.text[:500]}")
    except Exception as e:
        result["status"] = "error"
        result["errors"].append(f"Exception: {str(e)}")
    
    return result


@app.get("/clover/check-modifiers")
async def clover_check_modifiers_simple(
    merchantId: Optional[str] = Query(None),
    session: Optional[str] = Query(None),
    itemId: Optional[str] = Query(None),
    x_api_key: Optional[str] = Header(None),
):
    """
    Simple endpoint to check modifiers - just returns modifier info, nothing else.
    """
    merchant_id = _resolve_merchant_id_for_browser_or_api(merchantId, session, x_api_key)
    install = await _refresh_access_token_if_needed(merchant_id)
    rest_host = install.get("restHost") or _clover_rest_host(
        install.get("region") or CLOVER_REGION, install.get("env") or CLOVER_ENV
    )
    access_token = str(install.get("accessToken"))
    
    result = {
        "merchantId": merchant_id,
        "itemId": itemId,
        "all_modifier_groups": [],
        "item_modifier_groups": None,
        "errors": []
    }
    
    # Fetch ALL modifier groups
    try:
        all_groups_url = f"{rest_host}/v3/merchants/{merchant_id}/modifier_groups"
        async with httpx.AsyncClient(timeout=15.0) as client:
            groups_resp = await client.get(all_groups_url, headers={"Authorization": f"Bearer {access_token}"})
        
        result["groups_api_status"] = groups_resp.status_code
        result["groups_api_url"] = all_groups_url
        
        if groups_resp.status_code == 200:
            groups_data = groups_resp.json()
            groups = groups_data.get("elements") if isinstance(groups_data, dict) else (groups_data if isinstance(groups_data, list) else [])
            result["all_modifier_groups"] = groups if isinstance(groups, list) else []
            result["total_groups"] = len(result["all_modifier_groups"])
        else:
            result["errors"].append(f"Failed to fetch groups: {groups_resp.status_code} - {groups_resp.text[:200]}")
    except Exception as e:
        result["errors"].append(f"Exception fetching groups: {str(e)}")
    
    # If itemId provided, check its modifiers
    if itemId:
        try:
            item_groups_url = f"{rest_host}/v3/merchants/{merchant_id}/items/{itemId}/modifier_groups"
            async with httpx.AsyncClient(timeout=15.0) as client:
                item_groups_resp = await client.get(item_groups_url, headers={"Authorization": f"Bearer {access_token}"})
            
            result["item_groups_api_status"] = item_groups_resp.status_code
            result["item_groups_api_url"] = item_groups_url
            
            if item_groups_resp.status_code == 200:
                item_groups_data = item_groups_resp.json()
                item_groups = item_groups_data.get("elements") if isinstance(item_groups_data, dict) else (item_groups_data if isinstance(item_groups_data, list) else [])
                result["item_modifier_groups"] = item_groups if isinstance(item_groups, list) else []
            else:
                result["errors"].append(f"Failed to fetch item groups: {item_groups_resp.status_code} - {item_groups_resp.text[:200]}")
        except Exception as e:
            result["errors"].append(f"Exception fetching item groups: {str(e)}")
    
    return result


@app.get("/clover/debug/modifiers")
async def clover_debug_modifiers(
    merchantId: Optional[str] = None,
    session: Optional[str] = None,
    itemId: Optional[str] = None,
    locationId: Optional[str] = None,
    x_api_key: Optional[str] = Header(None),
):
    """
    Diagnostic endpoint to check if modifiers are actually configured in Clover.
    This shows:
    1. All modifier groups for the merchant
    2. All modifiers in each group
    3. If itemId is provided, checks if that item has modifierGroups linked
    4. Raw Clover API responses
    """
    merchant_id = _resolve_merchant_id_for_browser_or_api(merchantId, session, x_api_key)
    install = await _refresh_access_token_if_needed(merchant_id)
    rest_host = install.get("restHost") or _clover_rest_host(
        install.get("region") or CLOVER_REGION, install.get("env") or CLOVER_ENV
    )
    access_token = str(install.get("accessToken"))
    
    result = {
        "merchantId": merchant_id,
        "locationId": locationId,
        "itemId": itemId,
        "all_modifier_groups": [],
        "all_modifiers": [],
        "item_modifier_groups": None,
        "item_details": None,
        "errors": []
    }
    
    # 1. Fetch ALL modifier groups for the merchant
    try:
        all_groups_url = f"{rest_host}/v3/merchants/{merchant_id}/modifier_groups"
        async with httpx.AsyncClient(timeout=15.0) as client:
            groups_resp = await client.get(all_groups_url, headers={"Authorization": f"Bearer {access_token}"})
        
        if groups_resp.status_code == 200:
            groups_data = groups_resp.json()
            groups = groups_data.get("elements") if isinstance(groups_data, dict) else (groups_data if isinstance(groups_data, list) else [])
            result["all_modifier_groups"] = groups if isinstance(groups, list) else []
            
            # 2. Fetch modifiers for each group
            for group in result["all_modifier_groups"]:
                if not isinstance(group, dict):
                    continue
                group_id = group.get("id")
                if not group_id:
                    continue
                
                try:
                    modifiers_url = f"{rest_host}/v3/merchants/{merchant_id}/modifier_groups/{group_id}/modifiers"
                    mod_params = {}
                    if locationId:
                        mod_params["locationId"] = locationId
                    
                    async with httpx.AsyncClient(timeout=15.0) as client:
                        mod_resp = await client.get(modifiers_url, headers={"Authorization": f"Bearer {access_token}"}, params=mod_params if mod_params else None)
                    
                    if mod_resp.status_code == 200:
                        mod_data = mod_resp.json()
                        modifiers = mod_data.get("elements") if isinstance(mod_data, dict) else (mod_data if isinstance(mod_data, list) else [])
                        result["all_modifiers"].append({
                            "group_id": group_id,
                            "group_name": group.get("name"),
                            "modifiers": modifiers if isinstance(modifiers, list) else []
                        })
                    else:
                        result["errors"].append(f"Failed to fetch modifiers for group {group_id}: {mod_resp.status_code} - {mod_resp.text[:200]}")
                except Exception as e:
                    result["errors"].append(f"Exception fetching modifiers for group {group_id}: {str(e)}")
        else:
            result["errors"].append(f"Failed to fetch modifier groups: {groups_resp.status_code} - {groups_resp.text[:200]}")
    except Exception as e:
        result["errors"].append(f"Exception fetching modifier groups: {str(e)}")
    
    # 3. If itemId is provided, check if that item has modifierGroups
    if itemId:
        try:
            # Check item's modifier groups
            item_groups_url = f"{rest_host}/v3/merchants/{merchant_id}/items/{itemId}/modifier_groups"
            item_params = {}
            if locationId:
                item_params["locationId"] = locationId
            
            async with httpx.AsyncClient(timeout=15.0) as client:
                item_groups_resp = await client.get(item_groups_url, headers={"Authorization": f"Bearer {access_token}"}, params=item_params if item_params else None)
            
            if item_groups_resp.status_code == 200:
                item_groups_data = item_groups_resp.json()
                item_groups = item_groups_data.get("elements") if isinstance(item_groups_data, dict) else (item_groups_data if isinstance(item_groups_data, list) else [])
                result["item_modifier_groups"] = item_groups if isinstance(item_groups, list) else []
            else:
                result["errors"].append(f"Failed to fetch item modifier groups: {item_groups_resp.status_code} - {item_groups_resp.text[:200]}")
            
            # Also fetch the item itself to see its structure
            item_url = f"{rest_host}/v3/merchants/{merchant_id}/items/{itemId}"
            async with httpx.AsyncClient(timeout=15.0) as client:
                item_resp = await client.get(item_url, headers={"Authorization": f"Bearer {access_token}"})
            
            if item_resp.status_code == 200:
                result["item_details"] = item_resp.json()
            else:
                result["errors"].append(f"Failed to fetch item details: {item_resp.status_code} - {item_resp.text[:200]}")
        except Exception as e:
            result["errors"].append(f"Exception checking item modifiers: {str(e)}")
    
    return result


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

# Clover web dashboard backend (FastAPI + DynamoDB) + Vercel frontend

This repo is a **backend API** for a Clover **web / REST** app (merchant dashboard). It includes:

- **Clover OAuth v2** install flow (expiring tokens + refresh tokens)
- **DynamoDB** storage for installs/tokens + example order storage + webhook ingestion
- A sample endpoint that calls Clover REST APIs using the stored token

## Architecture (recommended)

- **Frontend**: Next.js on **Vercel**
- **Backend**: this FastAPI API (deployed on **Vercel** as Python serverless functions)
- **Database**: **DynamoDB**

This repo includes `vercel.json` + `api/index.py` so **all routes** are served by FastAPI on Vercel.

## DynamoDB tables

Create these tables in AWS DynamoDB:

### 1) `clover_installs` (required)

- **Partition key**: `merchantId` (String)
- **Attributes stored** (by this code):
  - `accessToken` (String)
  - `refreshToken` (String)
  - `expiresAtMs` (Number)
  - `env` (String: `prod` or `sandbox`)
  - `region` (String: `us` or `eu`)
  - `apiHost` (String)
  - `status` (String: `active`)
  - `updatedAtMs` (Number)

### 2) `clover_orders` (example)

- **Partition key**: `cloverOrderId` (String)

### 3) `clover_webhook_events` (example)

Recommended:
- **Partition key**: `eventId` (String)
- **Sort key**: `receivedAt` (String)

## Clover app setup

In the Clover Developer dashboard:

- Create an app (Web / REST)
- Choose required permissions (scopes)
- Set redirect/callback URL to your backend endpoint:
  - `https://YOUR_VERCEL_PROJECT.vercel.app/oauth/callback`

## Environment variables

Create a local `.env` (do **not** commit secrets) with:

```bash
# Required for your own API protection
API_KEY="dev-key"

# AWS
AWS_REGION="us-east-1"
AWS_ACCESS_KEY_ID="..."
AWS_SECRET_ACCESS_KEY="..."

# Optional for DynamoDB Local
# DYNAMODB_ENDPOINT_URL="http://localhost:8000"

# DynamoDB table names
DYNAMODB_INSTALLS_TABLE="clover_installs"
DYNAMODB_ORDERS_TABLE="clover_orders"
DYNAMODB_WEBHOOK_TABLE="clover_webhook_events"

# Clover OAuth v2
CLOVER_CLIENT_ID="..."
CLOVER_CLIENT_SECRET="..."
CLOVER_REDIRECT_URI="https://YOUR_BACKEND_DOMAIN/oauth/callback"
CLOVER_REGION="us"   # or "eu"

# OAuth state signing secret (required for /oauth/start)
OAUTH_STATE_SECRET="change-me"
```

## Local dev

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

## Endpoints

- `GET /oauth/start`
  - Redirects to Clover OAuth consent screen
- `GET /oauth/callback?code=...&state=...`
  - Exchanges code for tokens and stores install in DynamoDB
- `GET /menu?session=...`
  - Built-in menu browser + item selection/cart UI (quick way to view your Clover “test menu”)
- `GET /clover/menu/items?session=...`
  - Returns Clover inventory items (menu)
- `GET /clover/menu/categories?session=...`
  - Returns Clover categories
- `GET /clover/merchants/{merchantId}`
  - Example API call to Clover; requires header `x-api-key: $API_KEY`
- `POST /clover-webhook`
  - Stores raw webhook payloads in DynamoDB

## Deploy backend to Vercel

1) Push this repo to GitHub.

2) In Vercel, **New Project** → import the repo.

3) In **Project Settings → Environment Variables**, set:

- `API_KEY`
- `AWS_REGION`
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `DYNAMODB_INSTALLS_TABLE` (e.g. `clover_installs`)
- `DYNAMODB_ORDERS_TABLE` (e.g. `clover_orders`)
- `DYNAMODB_WEBHOOK_TABLE` (e.g. `clover_webhook_events`)
- `CLOVER_CLIENT_ID`
- `CLOVER_CLIENT_SECRET`
- `CLOVER_REDIRECT_URI` = `https://YOUR_VERCEL_PROJECT.vercel.app/oauth/callback`
- `CLOVER_ENV` = `sandbox` (for test merchants) or `prod`
- `CLOVER_REGION` = `us` or `eu`
- `OAUTH_STATE_SECRET`
- `SESSION_SECRET` (optional; defaults to `OAUTH_STATE_SECRET`)

4) Deploy. Your FastAPI API will be available at:

- `https://YOUR_VERCEL_PROJECT.vercel.app/`
- `https://YOUR_VERCEL_PROJECT.vercel.app/oauth/start`

## Showing Clover “test menu” items

1) In Clover app permissions, enable **Inventory / Items READ** (and optionally **Categories READ**).

2) If you’re using Clover sandbox/test merchants, set:

- `CLOVER_ENV=sandbox`

3) Reinstall the Clover app (new scopes only apply after reinstall).

4) Run install:

- Visit `https://YOUR_VERCEL_PROJECT.vercel.app/oauth/start`

After OAuth completes you’ll be redirected to:

- `https://YOUR_VERCEL_PROJECT.vercel.app/menu?session=...`

That page calls:

- `/clover/menu/items?session=...`

## Calling from Vercel frontend

From your Vercel frontend, call the backend using `fetch()`:

- After install, Clover will redirect to your `/oauth/callback`. In a real app you’ll redirect from there to your UI (e.g. `https://yourapp.vercel.app/app?merchantId=...`).
- Your UI then calls backend endpoints like `/clover/merchants/{merchantId}` (with `x-api-key`).

## Security notes

- Never expose `CLOVER_CLIENT_SECRET` in the frontend.
- Always validate OAuth `state` (this repo uses signed state).
- Consider encrypting tokens at rest (KMS) and keep IAM permissions least-privilege.


"""
Vercel Python entrypoint.

This file exists so Vercel can route all incoming requests to a single FastAPI app.
`vercel.json` maps /(.*) -> api/index.py
"""

from main import app  # FastAPI instance

# Some Vercel Python runtimes (or local emulators) may prefer a Lambda-style handler.
# Providing this doesn't hurt if unused.
try:
    from mangum import Mangum

    handler = Mangum(app)
except Exception:  # pragma: no cover
    handler = None


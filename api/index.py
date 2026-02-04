"""
Vercel Python entrypoint.

This file exists so Vercel can route all incoming requests to a single FastAPI app.
`vercel.json` maps /(.*) -> api/index.py
"""

from main import app  # FastAPI (ASGI) instance

# Important: do NOT export a `handler` symbol here.
# Vercel's Python runtime auto-detects HTTP handlers and can misinterpret non-class
# objects named `handler`, causing crashes like:
#   TypeError: issubclass() arg 1 must be a class

__all__ = ["app"]


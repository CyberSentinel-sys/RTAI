"""
relay_server/app.py
RTAI DMZ Relay Server — standalone FastAPI service.

Purpose
-------
This server sits in the DMZ (or an internet-connected staging machine) and
acts as the single outbound CVE data pipeline for air-gapped RTAI instances.
It aggregates CVE delta updates from upstream sources (NVD JSON feeds,
vendor advisories) and exposes them over a lightweight authenticated REST API
that the air-gapped RTAI node can pull from via ``scripts/sync_relay.py``.

Architecture::

    [Internet] → [DMZ Relay Server :8765] ← (pull) ← [Air-Gapped RTAI node]

Endpoints
---------
GET  /api/v1/health
    Liveness probe.  Returns server version and uptime.

GET  /api/v1/cve/delta?since=YYYY-MM-DD
    Returns a JSON delta of CVEs added or updated since *since*.
    If *since* is omitted, returns all CVEs in the local feed file.

POST /api/v1/cve/push
    (Admin) Accept a JSON array of CVE records and append them to the
    local feed file.  Protected by RELAY_ADMIN_TOKEN header.

Configuration (environment variables)
--------------------------------------
RELAY_CVE_FILE      Path to the local JSON CVE feed file.
                    Default: relay_server/data/cve_feed.json
RELAY_ADMIN_TOKEN   Static bearer token for the /cve/push endpoint.
                    Default: "changeme" (MUST be changed in production).
RELAY_HOST          Bind host (default: 0.0.0.0)
RELAY_PORT          Bind port (default: 8765)

Running
-------
    cd relay_server
    pip install -r requirements.txt
    uvicorn app:app --host 0.0.0.0 --port 8765

    # Or from project root:
    uvicorn relay_server.app:app --host 0.0.0.0 --port 8765
"""
from __future__ import annotations

import datetime
import json
import os
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import JSONResponse

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_HERE = Path(__file__).resolve().parent
_DEFAULT_FEED = _HERE / "data" / "cve_feed.json"

CVE_FILE    = Path(os.getenv("RELAY_CVE_FILE",    str(_DEFAULT_FEED)))
ADMIN_TOKEN = os.getenv("RELAY_ADMIN_TOKEN", "changeme")
_START_TIME = datetime.datetime.utcnow()

# Ensure the data directory and feed file exist on first run
CVE_FILE.parent.mkdir(parents=True, exist_ok=True)
if not CVE_FILE.exists():
    CVE_FILE.write_text(json.dumps([], indent=2), encoding="utf-8")

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="RTAI DMZ CVE Relay",
    description=(
        "Standalone relay server that aggregates CVE delta updates and serves "
        "them to air-gapped RTAI instances over a pull-based REST API."
    ),
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url=None,
)

# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------

def _require_admin(x_admin_token: str = Header(default="")) -> None:
    """Validate the X-Admin-Token header for write endpoints."""
    if not x_admin_token or x_admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid or missing X-Admin-Token")


# ---------------------------------------------------------------------------
# Feed helpers
# ---------------------------------------------------------------------------

def _load_feed() -> list[dict[str, Any]]:
    try:
        data = json.loads(CVE_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def _save_feed(records: list[dict[str, Any]]) -> None:
    CVE_FILE.write_text(json.dumps(records, indent=2), encoding="utf-8")


def _parse_date(s: str) -> datetime.date | None:
    try:
        return datetime.date.fromisoformat(s)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/v1/health", tags=["Relay"])
def health() -> JSONResponse:
    """Liveness probe — returns server version and uptime."""
    uptime_s = int((datetime.datetime.utcnow() - _START_TIME).total_seconds())
    feed = _load_feed()
    return JSONResponse({
        "status":      "ok",
        "version":     app.version,
        "uptime_sec":  uptime_s,
        "cve_count":   len(feed),
        "feed_file":   str(CVE_FILE),
        "timestamp":   datetime.datetime.utcnow().isoformat() + "Z",
    })


@app.get("/api/v1/cve/delta", tags=["CVE"])
def cve_delta(
    since: str = Query(
        default="",
        description="ISO date string (YYYY-MM-DD).  Only CVEs added/updated "
                    "on or after this date are returned.  Omit for full dump.",
    )
) -> JSONResponse:
    """
    Return a JSON delta of CVE records.

    Each record in the response has at minimum::

        {
            "cve_id":          "CVE-2024-6387",
            "description":     "...",
            "cvss_score":      8.1,
            "affected_product": "openssh",
            "updated_at":      "2024-07-01"
        }

    The air-gapped client (``scripts/sync_relay.py``) calls this endpoint
    and upserts the received records into its local SQLite CVE database.
    """
    feed = _load_feed()

    since_date = _parse_date(since)
    if since_date:
        feed = [
            r for r in feed
            if _parse_date(r.get("updated_at", "")) is not None
            and _parse_date(r.get("updated_at", "")) >= since_date  # type: ignore[operator]
        ]

    return JSONResponse({
        "relay_version": app.version,
        "since":         since or "all",
        "count":         len(feed),
        "records":       feed,
        "generated_at":  datetime.datetime.utcnow().isoformat() + "Z",
    })


@app.post("/api/v1/cve/push", tags=["CVE"], dependencies=[Depends(_require_admin)])
def cve_push(records: list[dict[str, Any]]) -> JSONResponse:
    """
    (Admin) Append new CVE records to the local feed file.

    Requires ``X-Admin-Token`` header matching ``RELAY_ADMIN_TOKEN``.

    Each record must contain at minimum::

        cve_id, description, cvss_score, affected_product

    ``updated_at`` is set to today if absent.
    """
    if not records:
        raise HTTPException(status_code=400, detail="No records provided")

    required = {"cve_id", "description", "cvss_score", "affected_product"}
    for i, r in enumerate(records):
        missing = required - set(r.keys())
        if missing:
            raise HTTPException(
                status_code=422,
                detail=f"Record {i} missing required fields: {sorted(missing)}",
            )
        r.setdefault("updated_at", datetime.date.today().isoformat())

    # Merge: existing records keyed by cve_id; new records overwrite on collision
    feed = _load_feed()
    existing: dict[str, dict[str, Any]] = {r["cve_id"]: r for r in feed}
    for r in records:
        existing[r["cve_id"]] = r
    _save_feed(list(existing.values()))

    return JSONResponse({
        "status":   "ok",
        "inserted": len(records),
        "total":    len(existing),
    })


# ---------------------------------------------------------------------------
# Dev entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host=os.getenv("RELAY_HOST", "0.0.0.0"),
        port=int(os.getenv("RELAY_PORT", "8765")),
        reload=False,
    )

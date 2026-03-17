#!/usr/bin/env python3
"""
scripts/sync_relay.py
Pull CVE delta updates from the RTAI DMZ Relay Server and insert them
into the local air-gapped SQLite CVE database.

Usage
-----
    # Sync all records (first run)
    python scripts/sync_relay.py --relay http://10.10.0.1:8765

    # Sync only CVEs updated since a specific date
    python scripts/sync_relay.py --relay http://10.10.0.1:8765 --since 2025-01-01

    # Dry-run: show what would be inserted without writing to disk
    python scripts/sync_relay.py --relay http://10.10.0.1:8765 --dry-run

Environment variables (alternative to CLI flags)
-------------------------------------------------
    RELAY_URL       Base URL of the DMZ relay server
    RELAY_SINCE     ISO date for delta sync (e.g. 2025-06-01)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date, datetime
from pathlib import Path
from typing import Any

# Ensure project root is on path when run as a script
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    import requests
except ImportError:
    print("[!] 'requests' is not installed. Run: pip install requests")
    sys.exit(1)

from core.local_cve_db import LocalCveDatabase  # noqa: E402


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_RELAY = os.getenv("RELAY_URL", "http://localhost:8765")
_DEFAULT_SINCE = os.getenv("RELAY_SINCE", "")
_DELTA_ENDPOINT = "/api/v1/cve/delta"
_HEALTH_ENDPOINT = "/api/v1/health"

_REQUIRED_FIELDS = {"cve_id", "description", "cvss_score", "affected_product"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _check_relay(base_url: str, timeout: int) -> bool:
    """Return True if the relay server is reachable and healthy."""
    try:
        resp = requests.get(base_url + _HEALTH_ENDPOINT, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        print(f"[+] Relay reachable — version {data.get('version', '?')}, "
              f"{data.get('cve_count', '?')} CVEs available")
        return True
    except requests.exceptions.ConnectionError:
        print(f"[!] Cannot connect to relay at {base_url}")
        return False
    except Exception as exc:  # noqa: BLE001
        print(f"[!] Relay health check failed: {exc}")
        return False


def _fetch_delta(base_url: str, since: str, timeout: int) -> list[dict[str, Any]]:
    """Fetch CVE records from the relay's /cve/delta endpoint."""
    params: dict[str, str] = {}
    if since:
        params["since"] = since

    url = base_url + _DELTA_ENDPOINT
    print(f"[*] Fetching delta from {url}" + (f" (since {since})" if since else " (full)"))

    resp = requests.get(url, params=params, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()

    records = data.get("records", [])
    print(f"[*] Received {len(records)} record(s) from relay "
          f"(relay reported count: {data.get('count', '?')})")
    return records


def _validate_record(r: dict[str, Any], idx: int) -> bool:
    """Return True if the record has all required fields with valid types."""
    missing = _REQUIRED_FIELDS - set(r.keys())
    if missing:
        print(f"    [!] Record {idx} skipped — missing fields: {sorted(missing)}")
        return False
    try:
        float(r["cvss_score"])
    except (TypeError, ValueError):
        print(f"    [!] Record {idx} ({r.get('cve_id', '?')}) skipped — "
              f"invalid cvss_score: {r.get('cvss_score')!r}")
        return False
    score = float(r["cvss_score"])
    if not 0.0 <= score <= 10.0:
        print(f"    [!] Record {idx} ({r.get('cve_id', '?')}) skipped — "
              f"cvss_score {score} out of range [0, 10]")
        return False
    return True


def _sync(
    relay_url: str,
    since: str = "",
    dry_run: bool = False,
    timeout: int = 30,
) -> int:
    """
    Pull CVE delta from the relay and upsert into the local SQLite DB.

    Returns the number of records successfully inserted.
    """
    if not _check_relay(relay_url, timeout):
        return 0

    records = _fetch_delta(relay_url, since, timeout)
    if not records:
        print("[+] Nothing to sync — local database is already up to date.")
        return 0

    valid = [r for i, r in enumerate(records) if _validate_record(r, i)]
    skipped = len(records) - len(valid)
    if skipped:
        print(f"    [!] {skipped} record(s) skipped due to validation errors")

    if dry_run:
        print(f"\n[DRY-RUN] Would insert {len(valid)} record(s):")
        for r in valid[:10]:
            print(f"    {r['cve_id']:25s}  score={float(r['cvss_score']):.1f}  "
                  f"product={r['affected_product']}")
        if len(valid) > 10:
            print(f"    ... and {len(valid) - 10} more")
        return len(valid)

    # Normalise and insert
    db_records = [
        {
            "cve_id":           r["cve_id"],
            "description":      str(r["description"]),
            "cvss_score":       float(r["cvss_score"]),
            "affected_product": str(r["affected_product"]).lower(),
        }
        for r in valid
    ]

    db = LocalCveDatabase()
    before = db.count()
    db.insert_many(db_records)
    after = db.count()
    db.close()

    new_count = after - before
    print(f"\n[+] Sync complete:")
    print(f"    Records received : {len(records)}")
    print(f"    Valid            : {len(valid)}")
    print(f"    New (upserted)   : {len(valid)}")
    print(f"    New unique CVEs  : {new_count}")
    print(f"    DB total         : {after}")
    print(f"    DB path          : {db.db_path}")
    return len(valid)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sync CVE deltas from the RTAI DMZ Relay into the local SQLite DB"
    )
    parser.add_argument(
        "--relay",
        default=_DEFAULT_RELAY,
        help=f"Base URL of the DMZ relay server (default: {_DEFAULT_RELAY})",
    )
    parser.add_argument(
        "--since",
        default=_DEFAULT_SINCE,
        help="Only fetch CVEs updated on or after this date (YYYY-MM-DD). "
             "Omit for a full sync.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be inserted without writing to the database",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="HTTP request timeout in seconds (default: 30)",
    )
    args = parser.parse_args()

    relay_url = args.relay.rstrip("/")

    print(f"\n{'=' * 60}")
    print("  RTAI DMZ Relay Sync")
    print(f"{'=' * 60}")
    print(f"  Relay  : {relay_url}")
    print(f"  Since  : {args.since or 'all'}")
    print(f"  Mode   : {'DRY-RUN' if args.dry_run else 'LIVE'}")
    print(f"{'=' * 60}\n")

    inserted = _sync(
        relay_url=relay_url,
        since=args.since,
        dry_run=args.dry_run,
        timeout=args.timeout,
    )

    sys.exit(0 if inserted >= 0 else 1)


if __name__ == "__main__":
    main()

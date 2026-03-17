#!/usr/bin/env python3
"""
scripts/generate_license.py
Generate a signed RTAI license token and write it to data/rtai.lic.

Usage
-----
Community (default, free):
    python scripts/generate_license.py

Enterprise (vendor side):
    python scripts/generate_license.py \\
        --tier enterprise \\
        --issued-to "ACME Corp" \\
        --expires 2027-01-01

The RTAI_LICENSE_SECRET env var must match the value set in
core/license_manager.py (or overridden on both sides).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.license_manager import generate_token, Tier  # noqa: E402

_ROOT   = Path(__file__).resolve().parents[1]
_OUT    = _ROOT / "data" / "rtai.lic"


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate an RTAI license key")
    parser.add_argument(
        "--tier",
        choices=[Tier.COMMUNITY, Tier.ENTERPRISE],
        default=Tier.COMMUNITY,
        help="License tier (default: community)",
    )
    parser.add_argument(
        "--issued-to",
        default="RTAI Community User",
        help="Licensee name embedded in the token",
    )
    parser.add_argument(
        "--expires",
        default="2027-01-01",
        help="Expiry date in YYYY-MM-DD format (default: 2027-01-01)",
    )
    parser.add_argument(
        "--out",
        default=str(_OUT),
        help=f"Output path (default: {_OUT})",
    )
    args = parser.parse_args()

    token = generate_token(
        tier=args.tier,
        issued_to=args.issued_to,
        expires=args.expires,
    )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(token + "\n", encoding="utf-8")

    print(f"[+] License generated ({args.tier.upper()})")
    print(f"    Issued to : {args.issued_to}")
    print(f"    Expires   : {args.expires}")
    print(f"    Written to: {out_path}")
    print(f"\n    Token (first 60 chars): {token[:60]}...")


if __name__ == "__main__":
    main()

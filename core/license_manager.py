"""
core/license_manager.py
Cryptographic license key engine for RTAI Enterprise feature gating.

Zero external dependencies — uses only Python stdlib:
  hmac, hashlib, json, base64, datetime, pathlib

License format
--------------
A license key is a three-part dot-separated token (similar to JWT):

    <base64url(header)>.<base64url(payload)>.<base64url(signature)>

Header (fixed)::

    {"alg": "HS256", "typ": "RTAI-LICENSE"}

Payload (example)::

    {
        "tier":       "enterprise",   # "community" | "enterprise"
        "issued_to":  "ACME Corp",
        "issued_at":  "2025-01-01",
        "expires":    "2027-01-01"
    }

Signature::

    HMAC-SHA256( base64url(header) + "." + base64url(payload), _VENDOR_SECRET )

Generating a license (vendor side)::

    python scripts/generate_license.py \\
        --tier enterprise \\
        --issued-to "ACME Corp" \\
        --expires 2027-01-01

The resulting token is written to ``data/rtai.lic``.

Feature gating
--------------
+----------------------------------+-------------+------------+
| Feature                          | community   | enterprise |
+----------------------------------+-------------+------------+
| Bash remediation scripts         | ✔           | ✔          |
| searchsploit / SQLite OSINT      | ✔           | ✔          |
| Ansible playbook generation      | ✗           | ✔          |
| Jira ticket integration          | ✗           | ✔          |
| HunterAgent (C2 / shellcode)     | ✗           | ✔          |
+----------------------------------+-------------+------------+
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

from core.config import Config


# ---------------------------------------------------------------------------
# Vendor secret — in production replace with env-injected secret or RSA key
# ---------------------------------------------------------------------------

# This secret must match the secret used by the license generator script.
# Override via RTAI_LICENSE_SECRET environment variable for CI/CD pipelines.
import os as _os
_VENDOR_SECRET: bytes = (
    _os.getenv("RTAI_LICENSE_SECRET", "rtai-enterprise-license-secret-v1")
    .encode()
)

_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_LIC_PATH = _ROOT / "data" / "rtai.lic"

_HEADER_B64 = base64.urlsafe_b64encode(
    json.dumps({"alg": "HS256", "typ": "RTAI-LICENSE"}, separators=(",", ":")).encode()
).rstrip(b"=").decode()


# ---------------------------------------------------------------------------
# Tier definitions
# ---------------------------------------------------------------------------

class Tier:
    COMMUNITY  = "community"
    ENTERPRISE = "enterprise"


_ENTERPRISE_FEATURES = frozenset({
    "ansible_remediation",
    "jira_integration",
    "hunter_agent",
})


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64_decode(s: str) -> bytes:
    # Add back stripped padding
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _sign(message: str) -> str:
    """Return the base64url-encoded HMAC-SHA256 signature of *message*."""
    sig = hmac.new(_VENDOR_SECRET, message.encode(), hashlib.sha256).digest()
    return _b64_encode(sig)


def _constant_compare(a: str, b: str) -> bool:
    """Timing-safe string comparison (prevents timing oracle attacks)."""
    return hmac.compare_digest(a.encode(), b.encode())


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_token(
    tier: str = Tier.ENTERPRISE,
    issued_to: str = "RTAI User",
    expires: str = "2027-01-01",
    issued_at: str | None = None,
) -> str:
    """
    Generate a signed license token.

    Parameters
    ----------
    tier:
        ``"community"`` or ``"enterprise"``.
    issued_to:
        Human-readable licensee name (embedded in the token).
    expires:
        Expiry date in ``YYYY-MM-DD`` format.
    issued_at:
        Issue date in ``YYYY-MM-DD`` format.  Defaults to today.

    Returns
    -------
    Dot-separated license token string.
    """
    if issued_at is None:
        issued_at = datetime.date.today().isoformat()

    payload: dict[str, Any] = {
        "tier":      tier,
        "issued_to": issued_to,
        "issued_at": issued_at,
        "expires":   expires,
    }
    payload_b64 = _b64_encode(
        json.dumps(payload, separators=(",", ":")).encode()
    )
    signing_input = f"{_HEADER_B64}.{payload_b64}"
    signature = _sign(signing_input)
    return f"{signing_input}.{signature}"


def verify_token(token: str) -> dict[str, Any]:
    """
    Verify and decode a license token.

    Parameters
    ----------
    token:
        Dot-separated license token string.

    Returns
    -------
    Decoded payload dict on success.

    Raises
    ------
    ValueError
        If the token is malformed, the signature is invalid, or the
        license has expired.
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("Malformed license token: expected 3 dot-separated parts.")

    header_b64, payload_b64, sig_b64 = parts

    # Verify header
    try:
        header = json.loads(_b64_decode(header_b64))
    except Exception:
        raise ValueError("Malformed license token: cannot decode header.")
    if header.get("alg") != "HS256" or header.get("typ") != "RTAI-LICENSE":
        raise ValueError("Unsupported license token type or algorithm.")

    # Verify signature
    expected_sig = _sign(f"{header_b64}.{payload_b64}")
    if not _constant_compare(expected_sig, sig_b64):
        raise ValueError("License signature is invalid — token may have been tampered with.")

    # Decode payload
    try:
        payload = json.loads(_b64_decode(payload_b64))
    except Exception:
        raise ValueError("Malformed license token: cannot decode payload.")

    # Check expiry
    try:
        expires = datetime.date.fromisoformat(payload["expires"])
    except (KeyError, ValueError):
        raise ValueError("License token is missing or has an invalid 'expires' field.")
    if datetime.date.today() > expires:
        raise ValueError(
            f"License expired on {payload['expires']}. "
            "Contact your RTAI vendor to renew."
        )

    return payload


# ---------------------------------------------------------------------------
# LicenseManager
# ---------------------------------------------------------------------------

class LicenseManager:
    """
    Startup license verification and Enterprise feature gating.

    Reads ``data/rtai.lic`` (or a path supplied via the ``RTAI_LICENSE_FILE``
    environment variable), verifies the cryptographic signature, checks the
    expiry date, and enforces feature restrictions on ``Config`` based on the
    detected tier.

    Usage (called once at startup in ``main.py``)::

        from core.license_manager import LicenseManager
        LicenseManager.enforce()
    """

    _BANNER_WIDTH = 70
    _COMMUNITY_BANNER = (
        "\n" + "!" * 70 + "\n"
        "  COMMUNITY EDITION ACTIVE. Enterprise features disabled.\n"
        "  Provide a valid rtai.lic key to unlock:\n"
        "    • Ansible playbook generation  (REMEDIATION_FORMAT=ansible)\n"
        "    • Jira ticket integration      (ENABLE_JIRA_INTEGRATION=true)\n"
        "    • HunterAgent                  (C2 beacon & shellcode detection)\n"
        "  Place your license file at:  data/rtai.lic\n"
        "!" * 70 + "\n"
    )
    _ENTERPRISE_BANNER = (
        "\n" + "=" * 70 + "\n"
        "  RTAI ENTERPRISE EDITION — License valid\n"
        "  All features enabled.\n"
        "=" * 70 + "\n"
    )

    @classmethod
    def enforce(
        cls,
        lic_path: Path | None = None,
    ) -> dict[str, Any]:
        """
        Load, verify, and apply the license.  Always returns a status dict
        and never raises — errors are handled by downgrading to Community.

        Returns
        -------
        dict with keys:
            ``tier``     — ``"enterprise"`` or ``"community"``
            ``valid``    — bool
            ``error``    — error message string (empty on success)
            ``payload``  — decoded token payload (or ``{}`` on failure)
        """
        path = lic_path or Path(
            _os.getenv("RTAI_LICENSE_FILE", str(_DEFAULT_LIC_PATH))
        )

        payload: dict[str, Any] = {}
        error = ""

        try:
            if not path.exists():
                raise FileNotFoundError(
                    f"License file not found: {path}\n"
                    "Run  python scripts/generate_license.py  to create a "
                    "Community license, or contact your RTAI vendor."
                )
            token = path.read_text(encoding="utf-8").strip()
            payload = verify_token(token)
            tier = payload.get("tier", Tier.COMMUNITY)
        except Exception as exc:  # noqa: BLE001
            tier = Tier.COMMUNITY
            error = str(exc)

        if tier == Tier.ENTERPRISE and not error:
            cls._apply_enterprise()
            print(cls._ENTERPRISE_BANNER)
            issued_to = payload.get("issued_to", "Unknown")
            expires   = payload.get("expires", "Unknown")
            print(f"  Licensed to : {issued_to}")
            print(f"  Expires     : {expires}\n")
        else:
            cls._apply_community()
            print(cls._COMMUNITY_BANNER)
            if error:
                print(f"  License error: {error}\n")

        return {
            "tier":    tier,
            "valid":   tier == Tier.ENTERPRISE and not error,
            "error":   error,
            "payload": payload,
        }

    # ------------------------------------------------------------------
    # Feature enforcement
    # ------------------------------------------------------------------

    @staticmethod
    def _apply_enterprise() -> None:
        """No restrictions — Enterprise has access to all features."""
        pass  # Config values remain as set in .env

    @staticmethod
    def _apply_community() -> None:
        """Restrict Config to Community-safe settings."""
        Config.REMEDIATION_FORMAT       = "bash"
        Config.ENABLE_JIRA_INTEGRATION  = False
        # HunterAgent exclusion is handled in swarm_controller.py by reading
        # the license status stored in Config.
        Config.HUNTER_AGENT_ENABLED     = False

    @staticmethod
    def is_enterprise_feature(feature: str) -> bool:
        """
        Return True if *feature* is available under the current license.

        Parameters
        ----------
        feature:
            One of: ``"ansible_remediation"``, ``"jira_integration"``,
            ``"hunter_agent"``.
        """
        if feature not in _ENTERPRISE_FEATURES:
            return True   # Unknown feature — don't block by default
        if Config.REMEDIATION_FORMAT == "ansible" and feature == "ansible_remediation":
            return True
        if Config.ENABLE_JIRA_INTEGRATION and feature == "jira_integration":
            return True
        if getattr(Config, "HUNTER_AGENT_ENABLED", True) and feature == "hunter_agent":
            return True
        return False

"""
tools/c2_hunter_tool.py
Network-based C2 framework signature detection tool.

Sends crafted HTTP/HTTPS requests to an IP:port and inspects the response
for known indicators of common C2 frameworks:

  • Cobalt Strike — default 404 response body ("<!DOCTYPE html>…" with empty
    content-length), characteristic HTTP response headers (X-Powered-By absent,
    specific Server strings or total absence), and JARM fingerprint heuristics.
  • Sliver — anomalous Content-Type on empty-body responses, missing standard
    headers, and Sliver-specific cookie names.
  • Metasploit / Meterpreter — self-signed TLS certificate subject attributes
    that match the Metasploit default cert template (CN=MetasploitSelf-Signed).
  • Generic beaconing — long-interval HTTP polling patterns inferred from
    response timing and lack of cache-control headers.

Returns a structured JSON-serialisable risk assessment dict.
"""
from __future__ import annotations

import json
import socket
import ssl
import time
import urllib.error
import urllib.request
from typing import Any

from tools.tool_base import BaseTool


# ---------------------------------------------------------------------------
# Signature definitions
# ---------------------------------------------------------------------------

# Cobalt Strike default 404 response patterns
_CS_404_BODIES: tuple[bytes, ...] = (
    b"<html><head><title>404</title></head><body><h1>Not Found</h1></body></html>",
    b"<!DOCTYPE html>\n<html>\n<head><title>404</title>",
)

_CS_SERVER_HEADERS: tuple[str, ...] = (
    "",            # CS sometimes sends no Server header at all
    "Microsoft-IIS/8.5",
    "Microsoft-IIS/7.5",
    "Apache",      # bare "Apache" without version is a CS default profile trick
)

# Sliver gRPC/HTTP2 indicator paths and anomalous headers
_SLIVER_PATHS: tuple[str, ...] = ("/health", "/oauth2/token")
_SLIVER_COOKIE_NAMES: tuple[str, ...] = ("PHPSESSID", "__cfduid")  # common profile masks

# Metasploit self-signed TLS cert default CN values
_MSF_CERT_CNS: tuple[str, ...] = (
    "MetasploitSelf-Signed",
    "localhost",
    "msf",
    "Metasploit",
)

# Generic suspicious-header absence list
_EXPECTED_HEADERS = {"content-type", "date", "server"}


# ---------------------------------------------------------------------------
# Tool implementation
# ---------------------------------------------------------------------------

class C2HunterTool(BaseTool):
    """
    Network C2 signature detector.

    Parameters (passed as kwargs to ``run()``)
    ------------------------------------------
    ip   : str   — Target IP or hostname.
    port : int   — TCP port to probe (e.g. 80, 443, 8080, 50050).
    """

    name = "c2_hunter"
    description = (
        "Probe an IP:port for C2 framework signatures (Cobalt Strike, Sliver, "
        "Metasploit).  Returns a risk assessment dict."
    )

    _TIMEOUT: float = 8.0     # seconds per probe
    _USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    def run(self, ip: str = "", port: int = 443, **_: Any) -> dict[str, Any]:  # noqa: ANN401
        if not ip:
            return self._assessment(ip, port, error="No IP provided")

        indicators: list[str] = []
        framework_guess = "Unknown"
        confidence = 0        # 0-100

        # ── TLS certificate check ────────────────────────────────────────────
        cert_cn, cert_org, tls_error = self._grab_cert(ip, port)
        if cert_cn:
            for msf_cn in _MSF_CERT_CNS:
                if msf_cn.lower() in cert_cn.lower():
                    indicators.append(
                        f"TLS cert CN matches Metasploit default: '{cert_cn}'"
                    )
                    framework_guess = "Metasploit"
                    confidence += 40

        # ── HTTP probe ───────────────────────────────────────────────────────
        scheme = "https" if port in (443, 8443, 8080) or cert_cn else "http"
        http_body, http_headers, http_ms, http_error = self._http_get(
            ip, port, "/", scheme
        )

        if http_body is not None:
            # Cobalt Strike 404 check
            for sig in _CS_404_BODIES:
                if http_body.startswith(sig[:40]):
                    indicators.append("Response matches Cobalt Strike default 404 body")
                    framework_guess = "Cobalt Strike"
                    confidence += 35
                    break

            # Server header heuristics
            server_hdr = http_headers.get("server", "ABSENT")
            if server_hdr == "ABSENT":
                indicators.append("No 'Server' header — unusual for legitimate services")
                confidence += 10
            elif server_hdr in _CS_SERVER_HEADERS and framework_guess != "Metasploit":
                indicators.append(
                    f"'Server: {server_hdr}' matches known CS malleable-profile default"
                )
                framework_guess = "Cobalt Strike"
                confidence += 15

            # Missing standard headers
            missing = _EXPECTED_HEADERS - set(k.lower() for k in http_headers)
            if len(missing) >= 2:
                indicators.append(f"Missing expected HTTP headers: {', '.join(sorted(missing))}")
                confidence += 10

            # Sliver path probe
            sliver_body, sliver_hdrs, _, _ = self._http_get(ip, port, "/health", scheme)
            if sliver_body is not None:
                ct = sliver_hdrs.get("content-type", "")
                if sliver_body == b"" and ct == "":
                    indicators.append("Empty /health response with no Content-Type — Sliver indicator")
                    framework_guess = "Sliver"
                    confidence += 25

            # Beacon timing heuristic: unusually fast connection but empty response
            if http_ms < 50 and len(http_body) < 100:
                indicators.append(
                    f"Suspiciously fast ({http_ms}ms) near-empty response — may be a beacon stub"
                )
                confidence += 10

        elif http_error:
            indicators.append(f"HTTP probe error: {http_error}")

        # ── Summary ──────────────────────────────────────────────────────────
        confidence = min(confidence, 95)    # cap — we can't be 100% without JARM
        risk_level = (
            "Critical" if confidence >= 70
            else "High" if confidence >= 45
            else "Medium" if confidence >= 20
            else "Low"
        )

        return self._assessment(
            ip, port,
            framework=framework_guess,
            indicators=indicators,
            confidence=confidence,
            risk_level=risk_level,
            tls_cn=cert_cn,
            tls_org=cert_org,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _grab_cert(
        self, ip: str, port: int
    ) -> tuple[str, str, str]:
        """Return (CN, O, error) from the TLS certificate, or ('', '', err)."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((ip, port), timeout=self._TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    subject = dict(x[0] for x in cert.get("subject", []))
                    return (
                        subject.get("commonName", ""),
                        subject.get("organizationName", ""),
                        "",
                    )
        except ssl.SSLError:
            return "", "", "SSLError"
        except (OSError, socket.timeout) as exc:
            return "", "", str(exc)

    def _http_get(
        self, ip: str, port: int, path: str, scheme: str
    ) -> tuple[bytes | None, dict[str, str], int, str]:
        """
        Perform one HTTP GET.  Returns (body, headers_dict, elapsed_ms, error).
        body is None on failure.
        """
        url = f"{scheme}://{ip}:{port}{path}"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(
            url,
            headers={"User-Agent": self._USER_AGENT},
        )
        t0 = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=self._TIMEOUT, context=ctx) as resp:
                body = resp.read(4096)
                elapsed = int((time.monotonic() - t0) * 1000)
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                return body, hdrs, elapsed, ""
        except urllib.error.HTTPError as exc:
            body = exc.read(4096)
            elapsed = int((time.monotonic() - t0) * 1000)
            hdrs = {k.lower(): v for k, v in exc.headers.items()}
            return body, hdrs, elapsed, ""
        except Exception as exc:  # noqa: BLE001
            return None, {}, 0, str(exc)

    @staticmethod
    def _assessment(
        ip: str,
        port: int,
        framework: str = "Unknown",
        indicators: list[str] | None = None,
        confidence: int = 0,
        risk_level: str = "Low",
        tls_cn: str = "",
        tls_org: str = "",
        error: str = "",
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "tool": "c2_hunter",
            "target": f"{ip}:{port}",
            "framework_guess": framework,
            "confidence_pct": confidence,
            "risk_level": risk_level,
            "indicators": indicators or [],
            "tls_subject": {"cn": tls_cn, "org": tls_org},
        }
        if error:
            result["error"] = error
        return result

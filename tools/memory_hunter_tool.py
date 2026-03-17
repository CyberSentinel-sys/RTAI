"""
tools/memory_hunter_tool.py
Host-based shellcode injection and process-hollowing detector.

Connects to a Linux host over SSH (using paramiko) and executes a lightweight
Python one-liner that scans every accessible /proc/<pid>/maps file for memory
regions that simultaneously satisfy ALL three conditions:

    1. rwxp  — readable, writable, and executable (private mapping)
    2. No backing file — the "pathname" column in /proc/<pid>/maps is empty
       or contains only a label like [heap], [stack], [vdso], [vsyscall]
    3. Not a known-benign anonymous region — JIT engines (Node.js V8, Java JVM,
       Python ctypes) are common false-positive sources; the remote script
       records them but tags them as "likely_jit" for the caller to filter.

This pattern (anonymous rwxp) is the primary in-memory indicator of:
  • Shellcode injection (e.g. via ptrace or /proc/<pid>/mem write)
  • Process hollowing (image replaced with injected payload)
  • Reflective DLL / SO injection

Requires
--------
- ``paramiko`` Python package (``pip install paramiko``)
- SSH access to the target (password or private key)
- The remote Python interpreter must be Python 3 (available as ``python3``)

Graceful degradation
--------------------
If paramiko is not installed the tool returns an informative error dict rather
than raising an ImportError, so the rest of the swarm pipeline continues.
"""
from __future__ import annotations

import textwrap
from typing import Any

from tools.tool_base import BaseTool


# ---------------------------------------------------------------------------
# Remote scanner payload (executed verbatim on the target via SSH)
# ---------------------------------------------------------------------------

_REMOTE_SCRIPT = textwrap.dedent("""
import os, json, re

ANON_LABELS = {'', '[heap]', '[stack]', '[stack:}', '[vdso]', '[vsyscall]', '[vvar]', '[anon]'}
JIT_COMM_PATTERNS = ('node', 'java', 'python', 'ruby', 'mono', 'dotnet', 'perf')

results = []
try:
    pids = [p for p in os.listdir('/proc') if p.isdigit()]
except OSError:
    print(json.dumps({'error': 'Cannot list /proc', 'suspicious_pids': []}))
    raise SystemExit

for pid in pids:
    maps_path = f'/proc/{pid}/maps'
    try:
        with open(maps_path) as fh:
            lines = fh.readlines()
    except OSError:
        continue

    try:
        with open(f'/proc/{pid}/comm') as fh:
            comm = fh.read().strip()
    except OSError:
        comm = 'unknown'

    likely_jit = any(p in comm.lower() for p in JIT_COMM_PATTERNS)

    for line in lines:
        parts = line.split()
        if len(parts) < 5:
            continue
        perms = parts[1]
        pathname = parts[5] if len(parts) > 5 else ''
        if perms == 'rwxp' and pathname in ANON_LABELS:
            addr_range = parts[0]
            start_hex, end_hex = addr_range.split('-')
            size_bytes = int(end_hex, 16) - int(start_hex, 16)
            results.append({
                'pid': int(pid),
                'comm': comm,
                'address_range': addr_range,
                'size_bytes': size_bytes,
                'permissions': perms,
                'pathname': pathname or '<anonymous>',
                'likely_jit': likely_jit,
            })

print(json.dumps({'suspicious_pids': results, 'error': ''}))
""").strip()


# ---------------------------------------------------------------------------
# Tool implementation
# ---------------------------------------------------------------------------

class MemoryHunterTool(BaseTool):
    """
    SSH-based anonymous rwxp memory region scanner.

    Parameters (passed as kwargs to ``run()``)
    ------------------------------------------
    ip         : str  — Target host IP or hostname.
    port       : int  — SSH port (default 22).
    username   : str  — SSH login username.
    password   : str  — SSH password (leave blank when using key_path).
    key_path   : str  — Path to a PEM private key file (preferred over password).
    timeout    : int  — SSH connection timeout in seconds (default 15).
    """

    name = "memory_hunter"
    description = (
        "SSH into a Linux host and scan /proc/<pid>/maps for anonymous rwxp "
        "memory regions — a primary indicator of shellcode injection or process "
        "hollowing.  Returns a list of suspicious PIDs."
    )

    def run(  # noqa: PLR0913
        self,
        ip: str = "",
        port: int = 22,
        username: str = "",
        password: str = "",
        key_path: str = "",
        timeout: int = 15,
        **_: Any,
    ) -> dict[str, Any]:
        if not ip or not username:
            return self._result(ip, port, error="ip and username are required")

        try:
            import paramiko  # noqa: PLC0415  (optional dep)
        except ImportError:
            return self._result(
                ip, port,
                error=(
                    "paramiko is not installed.  "
                    "Run: pip install paramiko"
                )
            )

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            connect_kwargs: dict[str, Any] = {
                "hostname": ip,
                "port": port,
                "username": username,
                "timeout": timeout,
                "look_for_keys": False,
                "allow_agent": False,
            }
            if key_path:
                connect_kwargs["key_filename"] = key_path
            elif password:
                connect_kwargs["password"] = password
            else:
                return self._result(ip, port, error="Provide either password or key_path")

            client.connect(**connect_kwargs)

            # Escape single quotes in the script and run it remotely
            escaped = _REMOTE_SCRIPT.replace("'", "'\\''")
            cmd = f"python3 -c '{escaped}'"

            _stdin, stdout, stderr = client.exec_command(cmd, timeout=30)
            out = stdout.read().decode(errors="replace").strip()
            err = stderr.read().decode(errors="replace").strip()

        except Exception as exc:  # noqa: BLE001
            return self._result(ip, port, error=f"SSH error: {exc}")
        finally:
            client.close()

        if not out:
            return self._result(
                ip, port,
                error=f"Remote script produced no output. stderr: {err[:300]}"
            )

        try:
            import json
            data = json.loads(out)
        except Exception:  # noqa: BLE001
            return self._result(
                ip, port,
                error=f"Could not parse remote output: {out[:300]}"
            )

        remote_err = data.get("error", "")
        hits: list[dict[str, Any]] = data.get("suspicious_pids", [])

        # Filter likely JIT false-positives but keep them in a separate list
        confirmed = [h for h in hits if not h.get("likely_jit")]
        jit_fp    = [h for h in hits if h.get("likely_jit")]

        risk_level = (
            "Critical" if confirmed
            else "Medium" if jit_fp
            else "Low"
        )

        return self._result(
            ip, port,
            confirmed_hits=confirmed,
            jit_false_positives=jit_fp,
            risk_level=risk_level,
            remote_error=remote_err,
        )

    @staticmethod
    def _result(
        ip: str,
        port: int,
        confirmed_hits: list[dict[str, Any]] | None = None,
        jit_false_positives: list[dict[str, Any]] | None = None,
        risk_level: str = "Low",
        error: str = "",
        remote_error: str = "",
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "tool": "memory_hunter",
            "target": f"{ip}:{port}",
            "risk_level": risk_level,
            "confirmed_anonymous_rwxp": confirmed_hits or [],
            "jit_false_positives": jit_false_positives or [],
            "suspicious_pid_count": len(confirmed_hits or []),
        }
        if error:
            result["error"] = error
        if remote_error:
            result["remote_error"] = remote_error
        return result

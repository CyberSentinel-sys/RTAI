"""
agents/scout_agent.py

Standalone scout agent combining nmap service scanning with optional
scapy-based host discovery to produce a structured attack-surface report.

Scan pipeline
-------------
1. **Target classification**
   - Single IP / hostname → standard single-host scan (original behaviour).
   - CIDR range (e.g. ``192.168.1.0/24``) → two-phase subnet mode (see below).

2. **Subnet mode — two-phase stealthy scan**
   a. **ARP host discovery** (preferred — scapy + root + local subnet)
      - Broadcasts ARP requests across the entire CIDR; only live hosts reply.
      - Produces a whitelist of active IPs — nmap never touches dead hosts,
        so scan time and network noise scale with *live* hosts, not subnet size.
   b. **Nmap ping sweep** (fallback — scapy absent or not root)
      - Root:    ``-sn -PE -PS22,80,443 -T4``  (SYN + ICMP probes)
      - No root: ``-sn -T4``                    (TCP connect ping)
      - Same goal: identify live hosts before running service scans.
   c. **Full-subnet fallback** — if both discovery methods find zero hosts,
      nmap receives the original CIDR and performs its own host detection.

3. **Service scan** (nmap, targeted)
   - CIDR target: scans **only the live IPs** found in step 2 (space-separated).
   - Single host: scans the target directly (no pre-scan required).
   - Root available → stealthy SYN scan  ``-sS -sV -O -Pn --open -T2``
   - No root         → TCP connect scan  ``-sT -sV -Pn --open -T3``
   - Falls back with an error entry when the nmap binary is missing.

4. **Attack-surface summary** (LLM)
   - LLM receives the full structured result and returns a narrative analysis
     with prioritised risks.

Structured output (stored in ``state.tool_outputs["scout"]``)
--------------------------------------------------------------
{
  "target": "<original ip or cidr>",
  "scan_metadata": {
    "timestamp": "...",
    "nmap_available": true,
    "scapy_available": true,
    "run_as_root": false,
    "scan_mode": "tcp_connect | syn_stealth | unavailable",
    "nmap_args": "...",
    "is_subnet_scan": true,
    "live_hosts_discovered": 5,
    "nmap_scan_target": "10.0.0.1 10.0.0.4 10.0.0.7"
  },
  "hosts": [
    {
      "ip": "...",
      "hostname": "...",
      "state": "up",
      "discovery_method": "arp | icmp | nmap_ping | nmap",
      "os_guesses": [{"name": "...", "accuracy": "..."}],
      "open_ports": [
        {
          "port": 22,
          "protocol": "tcp",
          "service": "ssh",
          "product": "OpenSSH",
          "version": "8.4",
          "extra_info": "...",
          "risk_hint": "..."
        }
      ]
    }
  ],
  "attack_surface": {
    "total_hosts_up": 5,
    "total_open_ports": 12,
    "high_risk_ports": [22, 445],
    "llm_summary": "..."
  },
  "errors": []
}
"""
from __future__ import annotations

import ipaddress
import json
import os
import socket
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from agents.base_agent import BaseAgent
from core.state import RTAIState

# ---------------------------------------------------------------------------
# Risk hints for well-known ports
# ---------------------------------------------------------------------------

_PORT_RISK: dict[int, str] = {
    21:    "FTP – plaintext credentials; anonymous login common",
    22:    "SSH – prime brute-force target if credentials are weak",
    23:    "Telnet – plaintext credentials; deprecated protocol",
    25:    "SMTP – relay abuse, user enumeration, info disclosure",
    53:    "DNS – zone transfer possible, cache poisoning vector",
    69:    "TFTP – unauthenticated file read/write",
    80:    "HTTP – web attack surface (SQLi, XSS, path traversal, RCE)",
    110:   "POP3 – plaintext credential exposure",
    111:   "RPC portmapper – pivot for lateral movement",
    135:   "MS-RPC – EternalBlue family of exploits",
    139:   "NetBIOS – SMB enumeration and credential relay",
    143:   "IMAP – plaintext credential theft possible",
    161:   "SNMP – community string abuse, info disclosure",
    389:   "LDAP – enumeration, null bind, credential relay",
    443:   "HTTPS – web attack surface",
    445:   "SMB – EternalBlue, PrintNightmare, relay attacks",
    512:   "rexec – plaintext remote execution",
    513:   "rlogin – plaintext remote login",
    514:   "RSH – potentially unauthenticated remote shell",
    1433:  "MSSQL – credential attacks, xp_cmdshell RCE",
    1521:  "Oracle DB – credential attack, TNS poison",
    2049:  "NFS – unauthenticated mount may expose sensitive files",
    2181:  "ZooKeeper – typically unauthenticated, config disclosure",
    3306:  "MySQL – credential attack, file read via LOAD DATA",
    3389:  "RDP – BlueKeep, brute-force, MitM downgrade",
    4444:  "Metasploit default listener – likely backdoor or C2",
    5432:  "PostgreSQL – credential attack, COPY command abuse",
    5900:  "VNC – weak/no auth, unencrypted desktop access",
    5985:  "WinRM HTTP – lateral movement, credential relay",
    5986:  "WinRM HTTPS – lateral movement",
    6379:  "Redis – unauthenticated RCE frequently observed in wild",
    7077:  "Spark master – unauthenticated RCE via job submission",
    8080:  "HTTP alt – web attack surface",
    8443:  "HTTPS alt – web attack surface",
    8888:  "Jupyter Notebook – unauthenticated code execution",
    9200:  "Elasticsearch – unauthenticated data access / RCE via scripts",
    27017: "MongoDB – unauthenticated access frequently exposed",
}

# Ports considered high-risk for the summary metrics
_HIGH_RISK_PORTS: frozenset[int] = frozenset(_PORT_RISK.keys())


# ---------------------------------------------------------------------------
# Scout agent
# ---------------------------------------------------------------------------

class ScoutAgent(BaseAgent):
    """
    Scout agent: stealthy, structured reconnaissance.

    For single-IP targets uses scapy (when available and privileged) for host
    discovery and nmap for detailed service/version/OS scanning.

    For CIDR subnet targets performs a two-phase scan:
      1. Stealthy ARP sweep (scapy, root) to find live hosts.
      2. Nmap service scan against only the live IPs — dead hosts are never
         probed, reducing both scan duration and network noise.

    All results are merged into ``RTAIState`` and stored under
    ``tool_outputs["scout"]``.

    Compatible with both standalone usage and the ``SwarmController`` pipeline
    via ``BaseAgent.execute()``.
    """

    role = "Scout"
    goal = (
        "Perform stealthy target reconnaissance. "
        "Enumerate live hosts, open ports, service versions, and OS fingerprints. "
        "Identify the highest-value attack surface for the next pipeline stage."
    )

    # ------------------------------------------------------------------
    # BaseAgent interface
    # ------------------------------------------------------------------

    def run(self, state: RTAIState) -> dict[str, Any]:
        target = state.target
        errors: list[str] = []
        is_subnet = self._is_cidr(target)

        # --- 1. Dependency / privilege checks ----------------------------
        nmap_ok, nmap_err = self._check_nmap()
        scapy_ok, scapy_err = self._check_scapy()
        root = self._is_root()

        if not nmap_ok:
            errors.append(nmap_err)
            result = self._empty_result(target, root, scapy_ok, is_subnet, errors)
            return self._build_partial(result)

        if not scapy_ok:
            errors.append(scapy_err)

        # --- 2. Host discovery -------------------------------------------
        discovered: dict[str, str] = {}  # ip → discovery_method
        # scan_target: what nmap will actually receive; narrowed to live IPs
        # for CIDR targets, kept as the original string for single hosts.
        scan_target = target

        if is_subnet:
            # ------------------------------------------------------------------
            # Subnet mode: discover live hosts first, then scan only them.
            # ------------------------------------------------------------------
            if scapy_ok and root:
                # Phase 2a — stealthy ARP sweep (preferred for local ranges)
                arp_found, arp_errors = self._arp_scan(target)
                errors.extend(arp_errors)
                discovered.update(arp_found)

                if arp_found:
                    scan_target = " ".join(sorted(arp_found))
                    errors.append(
                        f"ARP sweep: {len(arp_found)} live host(s) found; "
                        "nmap service scan limited to those IPs."
                    )
                else:
                    errors.append(
                        "ARP sweep found no live hosts; "
                        "falling back to full-subnet nmap scan."
                    )
            else:
                # Phase 2b — nmap ping sweep fallback
                if not root:
                    errors.append(
                        "Root not available; using nmap ping sweep (-sn) "
                        "for host discovery instead of ARP."
                    )
                ping_found, ping_errors = self._nmap_ping_sweep(target, root)
                errors.extend(ping_errors)

                if ping_found:
                    discovered = {ip: "nmap_ping" for ip in ping_found}
                    scan_target = " ".join(sorted(ping_found))
                    errors.append(
                        f"Nmap ping sweep: {len(ping_found)} live host(s) found; "
                        "service scan limited to those IPs."
                    )
                else:
                    errors.append(
                        "Nmap ping sweep found no live hosts; "
                        "falling back to full-subnet service scan."
                    )
        else:
            # ------------------------------------------------------------------
            # Single-host / non-CIDR mode — original behaviour unchanged.
            # ------------------------------------------------------------------
            if scapy_ok and root:
                found, disc_errors = self._scapy_discover(target)
                discovered.update(found)
                errors.extend(disc_errors)
            else:
                if not root:
                    errors.append(
                        "Scapy host discovery skipped: not running as root. "
                        "Nmap will probe all targets directly (-Pn)."
                    )

        # --- 2b. SCAN_SELF injection -------------------------------------
        # When SCAN_SELF=True, always include 127.0.0.1 and the machine's
        # local LAN IP in the scan queue, regardless of discovery results.
        from core.config import Config  # local import avoids circular deps
        if Config.SCAN_SELF:
            self_ips = self._get_self_ips()
            new_self = [ip for ip in self_ips if ip not in discovered]
            for ip in new_self:
                discovered[ip] = "self"
            if new_self:
                errors.append(
                    f"SCAN_SELF: force-adding {new_self} to scan queue."
                )
            # Merge into scan_target (space-separated list)
            existing = set(scan_target.split()) if scan_target != target else set()
            if is_subnet:
                # scan_target may already be a list of live IPs or the CIDR
                existing = set(scan_target.split())
            else:
                existing = {scan_target}
            combined = existing | set(self_ips)
            scan_target = " ".join(sorted(combined))

        # --- 3. Nmap service scan (targeted) ----------------------------
        scan_mode = "syn_stealth" if root else "tcp_connect"
        nmap_args = (
            "-sS -sV -O -Pn --open -T2"
            if root else
            "-sT -sV -Pn --open -T3"
        )
        nmap_data, nmap_errors = self._nmap_scan(scan_target, nmap_args)
        errors.extend(nmap_errors)

        # --- 4. Build structured result ----------------------------------
        result = self._build_structured_result(
            target=target,
            scan_target=scan_target,
            is_subnet=is_subnet,
            nmap_data=nmap_data,
            discovered=discovered,
            scan_mode=scan_mode,
            nmap_available=nmap_ok,
            scapy_available=scapy_ok,
            root=root,
            errors=errors,
        )

        # --- 5. LLM attack-surface summary ------------------------------
        result["attack_surface"]["llm_summary"] = self._llm_summary(result)

        return self._build_partial(result)

    # ------------------------------------------------------------------
    # Dependency / privilege helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_root() -> bool:
        """Return True if the process has root / administrator privileges."""
        return os.geteuid() == 0

    @staticmethod
    def _check_nmap() -> tuple[bool, str]:
        """Return (available, error_message)."""
        try:
            import nmap  # noqa: F401
            import shutil
            if shutil.which("nmap") is None:
                return False, "nmap binary not found on PATH. Install nmap to enable scanning."
            return True, ""
        except ImportError:
            return False, (
                "python-nmap is not installed. "
                "Run: pip install python-nmap"
            )

    @staticmethod
    def _check_scapy() -> tuple[bool, str]:
        """Return (available, error_message)."""
        try:
            import scapy.all  # noqa: F401
            return True, ""
        except ImportError:
            return False, (
                "scapy is not installed; host discovery will be skipped. "
                "Run: pip install scapy"
            )

    # ------------------------------------------------------------------
    # Target classification
    # ------------------------------------------------------------------

    @staticmethod
    def _is_cidr(target: str) -> bool:
        """
        Return True if *target* is a CIDR network range (contains ``/``).

        Examples
        --------
        >>> ScoutAgent._is_cidr("192.168.1.0/24")
        True
        >>> ScoutAgent._is_cidr("10.0.0.1")
        False
        >>> ScoutAgent._is_cidr("scanme.nmap.org")
        False
        """
        if "/" not in target:
            return False
        try:
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            return False

    # ------------------------------------------------------------------
    # Scapy host discovery
    # ------------------------------------------------------------------

    def _scapy_discover(self, target: str) -> tuple[dict[str, str], list[str]]:
        """
        Attempt host discovery using scapy (single-host / non-subnet path).

        Returns
        -------
        (discovered, errors) where *discovered* maps ip → method string.
        """
        discovered: dict[str, str] = {}
        errors: list[str] = []

        if self._is_local_cidr(target):
            arp_found, arp_errors = self._arp_scan(target)
            discovered.update(arp_found)
            errors.extend(arp_errors)
        else:
            hosts = self._expand_targets(target)
            icmp_found, icmp_errors = self._icmp_ping(hosts)
            discovered.update(icmp_found)
            errors.extend(icmp_errors)

        return discovered, errors

    @staticmethod
    def _is_local_cidr(target: str) -> bool:
        """Return True if *target* is a private RFC-1918 network range."""
        try:
            net = ipaddress.ip_network(target, strict=False)
            return net.is_private
        except ValueError:
            return False

    @staticmethod
    def _expand_targets(target: str) -> list[str]:
        """Expand a CIDR or return a single-item list for a plain IP."""
        try:
            net = ipaddress.ip_network(target, strict=False)
            hosts = [str(h) for h in net.hosts()]
            return hosts if hosts else [target]
        except ValueError:
            return [target]

    @staticmethod
    def _arp_scan(target: str) -> tuple[dict[str, str], list[str]]:
        """
        ARP scan a local subnet.  Requires root and scapy.

        Sends a broadcast ARP request to *target* (CIDR or single IP) and
        collects replies.  Only hosts that are genuinely reachable respond,
        making this the stealthiest and fastest live-host discovery method
        for local networks.

        Returns ({ip: "arp"}, errors).
        """
        discovered: dict[str, str] = {}
        errors: list[str] = []
        try:
            from scapy.all import ARP, Ether, srp  # type: ignore[import]
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
            answered, _ = srp(pkt, timeout=3, verbose=0)
            for _, rcv in answered:
                discovered[rcv.psrc] = "arp"
        except PermissionError:
            errors.append(
                "ARP scan failed: permission denied. "
                "Run as root to enable scapy ARP discovery."
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"ARP scan error: {exc}")
        return discovered, errors

    @staticmethod
    def _icmp_ping(hosts: list[str]) -> tuple[dict[str, str], list[str]]:
        """
        ICMP ping a list of hosts.  Requires root and scapy.

        Returns ({ip: "icmp"}, errors).
        """
        discovered: dict[str, str] = {}
        errors: list[str] = []
        try:
            from scapy.all import ICMP, IP, sr1  # type: ignore[import]
            for host in hosts:
                try:
                    pkt = IP(dst=host) / ICMP()
                    reply = sr1(pkt, timeout=1, verbose=0)
                    if reply is not None:
                        discovered[host] = "icmp"
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"ICMP ping failed for {host}: {exc}")
        except PermissionError:
            errors.append(
                "ICMP ping failed: permission denied. "
                "Run as root to enable scapy ICMP discovery."
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"ICMP discovery error: {exc}")
        return discovered, errors

    # ------------------------------------------------------------------
    # Nmap helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _nmap_ping_sweep(target: str, root: bool) -> tuple[list[str], list[str]]:
        """
        Nmap-based host discovery sweep (``-sn`` — no port scan).

        Used as a fallback when scapy is unavailable or the process is not
        running as root.

        Parameters
        ----------
        target:
            CIDR range or IP to sweep.
        root:
            When True, adds ``-PE -PS22,80,443`` for SYN/ICMP probes (more
            reliable).  When False, uses only TCP connect pings.

        Returns
        -------
        (live_ips, errors)
        """
        errors: list[str] = []
        live: list[str] = []
        try:
            import nmap  # type: ignore[import]
            scanner = nmap.PortScanner()
            args = "-sn -PE -PS22,80,443 -T4" if root else "-sn -T4"
            scanner.scan(hosts=target, arguments=args)
            for host in scanner.all_hosts():
                if scanner[host].state() == "up":
                    live.append(host)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"Nmap ping sweep error: {exc}")
        return live, errors

    @staticmethod
    def _nmap_scan(target: str, arguments: str) -> tuple[dict[str, Any], list[str]]:
        """
        Run nmap with the given *arguments* against *target*.

        *target* may be a single IP, a space-separated list of IPs (produced
        by the subnet live-host filter), or a CIDR range.

        Returns (raw_nmap_dict, errors).
        """
        errors: list[str] = []
        try:
            import nmap  # type: ignore[import]
            scanner = nmap.PortScanner()
            scanner.scan(hosts=target, arguments=arguments)

            hosts_out: list[dict[str, Any]] = []
            for host in scanner.all_hosts():
                entry: dict[str, Any] = {
                    "ip": host,
                    "hostname": scanner[host].hostname(),
                    "state": scanner[host].state(),
                    "os_guesses": [],
                    "ports": [],
                }
                # OS
                try:
                    for m in scanner[host].get("osmatch", [])[:3]:
                        entry["os_guesses"].append(
                            {"name": m.get("name", ""), "accuracy": m.get("accuracy", "")}
                        )
                except (KeyError, TypeError):
                    pass
                # Ports
                for proto in scanner[host].all_protocols():
                    for port, data in scanner[host][proto].items():
                        entry["ports"].append(
                            {
                                "port": port,
                                "protocol": proto,
                                "state": data.get("state"),
                                "service": data.get("name", ""),
                                "product": data.get("product", ""),
                                "version": data.get("version", ""),
                                "extra_info": data.get("extrainfo", ""),
                            }
                        )
                hosts_out.append(entry)

            return {"hosts": hosts_out, "scan_args": arguments}, errors

        except nmap.PortScannerError as exc:
            errors.append(f"Nmap scan error: {exc}")
            return {"hosts": [], "scan_args": arguments}, errors
        except Exception as exc:  # noqa: BLE001
            errors.append(f"Unexpected nmap error: {exc}")
            return {"hosts": [], "scan_args": arguments}, errors

    # ------------------------------------------------------------------
    # Self-IP resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _get_self_ips() -> list[str]:
        """
        Return the loopback address and the machine's primary LAN IP.

        The LAN IP is determined by opening a UDP socket toward a public
        address (no data is actually sent) and reading the bound local
        address — this reliably selects the correct outbound interface
        without requiring root or parsing routing tables.
        """
        ips: list[str] = ["127.0.0.1"]
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            lan_ip = s.getsockname()[0]
            s.close()
            if lan_ip and lan_ip != "127.0.0.1":
                ips.append(lan_ip)
        except Exception:  # noqa: BLE001
            pass
        return ips

    # ------------------------------------------------------------------
    # Result assembly
    # ------------------------------------------------------------------

    def _build_structured_result(
        self,
        target: str,
        scan_target: str,
        is_subnet: bool,
        nmap_data: dict[str, Any],
        discovered: dict[str, str],
        scan_mode: str,
        nmap_available: bool,
        scapy_available: bool,
        root: bool,
        errors: list[str],
    ) -> dict[str, Any]:
        import datetime

        hosts_out: list[dict[str, Any]] = []
        total_open = 0
        high_risk: list[int] = []

        for h in nmap_data.get("hosts", []):
            ip = h["ip"]
            open_ports: list[dict[str, Any]] = []

            for p in h.get("ports", []):
                port_num: int = p["port"]
                risk = _PORT_RISK.get(port_num, "")
                open_ports.append(
                    {
                        "port": port_num,
                        "protocol": p["protocol"],
                        "service": p["service"],
                        "product": p["product"],
                        "version": p["version"],
                        "extra_info": p["extra_info"],
                        "risk_hint": risk,
                    }
                )
                if port_num in _HIGH_RISK_PORTS:
                    high_risk.append(port_num)
                total_open += 1

            hosts_out.append(
                {
                    "ip": ip,
                    "hostname": h["hostname"],
                    "state": h["state"],
                    "discovery_method": discovered.get(ip, "nmap"),
                    "os_guesses": h["os_guesses"],
                    "open_ports": open_ports,
                }
            )

        # nmap_scan_target: only stored when it differs from the original target
        # (i.e. when we narrowed a CIDR down to specific live IPs).
        narrowed = scan_target if (is_subnet and scan_target != target) else None

        return {
            "target": target,
            "scan_metadata": {
                "timestamp": datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z",
                "nmap_available": nmap_available,
                "scapy_available": scapy_available,
                "run_as_root": root,
                "scan_mode": scan_mode,
                "nmap_args": nmap_data.get("scan_args", ""),
                "is_subnet_scan": is_subnet,
                "live_hosts_discovered": len(discovered),
                "nmap_scan_target": narrowed,
            },
            "hosts": hosts_out,
            "attack_surface": {
                "total_hosts_up": len(hosts_out),
                "total_open_ports": total_open,
                "high_risk_ports": sorted(set(high_risk)),
                "llm_summary": "",  # filled in after
            },
            "errors": errors,
        }

    def _empty_result(
        self,
        target: str,
        root: bool,
        scapy_available: bool,
        is_subnet: bool,
        errors: list[str],
    ) -> dict[str, Any]:
        import datetime
        return {
            "target": target,
            "scan_metadata": {
                "timestamp": datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z",
                "nmap_available": False,
                "scapy_available": scapy_available,
                "run_as_root": root,
                "scan_mode": "unavailable",
                "nmap_args": "",
                "is_subnet_scan": is_subnet,
                "live_hosts_discovered": 0,
                "nmap_scan_target": None,
            },
            "hosts": [],
            "attack_surface": {
                "total_hosts_up": 0,
                "total_open_ports": 0,
                "high_risk_ports": [],
                "llm_summary": "Scan could not be completed — see errors.",
            },
            "errors": errors,
        }

    # ------------------------------------------------------------------
    # LLM summary
    # ------------------------------------------------------------------

    def _llm_summary(self, result: dict[str, Any]) -> str:
        """Ask the LLM to narrate the attack surface from the structured result."""
        messages = [
            SystemMessage(content=self._system_prompt()),
            HumanMessage(
                content=(
                    "Below is a structured recon result for an authorised engagement.\n\n"
                    f"```json\n{json.dumps(result, indent=2)}\n```\n\n"
                    "Provide a concise attack-surface assessment covering:\n"
                    "1. Overall risk rating (Critical / High / Medium / Low / Minimal)\n"
                    "2. Top 3 highest-priority attack vectors with brief justification\n"
                    "3. Services that should be investigated first and why\n"
                    "4. Any anomalies or unexpected findings\n"
                    "Be specific and technical; avoid generic advice."
                )
            ),
        ]
        try:
            response = self.llm.invoke(messages)
            return response.content
        except Exception as exc:  # noqa: BLE001
            return f"LLM summary unavailable: {exc}"

    # ------------------------------------------------------------------
    # State partial builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_partial(result: dict[str, Any]) -> dict[str, Any]:
        """Convert the structured result into a partial RTAIState dict."""
        surface = result["attack_surface"]
        meta = result["scan_metadata"]
        finding = {
            "phase": "scout",
            "target": result["target"],
            "scan_mode": meta["scan_mode"],
            "is_subnet_scan": meta["is_subnet_scan"],
            "live_hosts_discovered": meta["live_hosts_discovered"],
            "hosts_up": surface["total_hosts_up"],
            "open_ports": surface["total_open_ports"],
            "high_risk_ports": surface["high_risk_ports"],
            "summary": surface["llm_summary"],
            "errors": result["errors"],
        }
        return {
            "tool_outputs": {"scout": result},
            "findings": [finding],
            "current_step": "scout_complete",
        }


# =============================================================================
# Backward-compatibility shim — was agents/recon_agent.py
# ReconAgent has been consolidated into this module.  Any existing imports of
# ``from agents.recon_agent import ReconAgent`` continue to work via
# ``from agents.scout_agent import ReconAgent``.
# =============================================================================

import json as _json  # noqa: E402  (already imported above, alias avoids re-import)


class ReconAgent(BaseAgent):
    """
    Backward-compatibility alias for the legacy ReconAgent.

    The original ReconAgent used a simple nmap-via-ToolRegistry approach.
    Its logic is preserved here verbatim so that any pipeline still referencing
    ``ReconAgent`` continues to work without modification.

    For new engagements prefer ``ScoutAgent``, which performs stealthy two-phase
    host discovery and produces a richer structured result.
    """

    role = "Reconnaissance Specialist"
    goal = "Enumerate hosts, open ports, running services, and OS information."

    def run(self, state: RTAIState) -> dict[str, Any]:
        """
        Run a direct nmap scan via ToolRegistry and return LLM-annotated findings.

        Args:
            state: Current shared engagement state containing the target.

        Returns:
            Partial state dict with ``tool_outputs["nmap"]``, a ``findings``
            entry with ``phase="recon"``, and ``current_step="recon_complete"``.
        """
        from tools.tool_registry import ToolRegistry
        from langchain_core.messages import HumanMessage, SystemMessage

        registry = ToolRegistry.default()
        nmap_result = registry.run("nmap", target=state.target)

        messages = [
            SystemMessage(content=self._system_prompt()),
            HumanMessage(
                content=(
                    f"Target: {state.target}\n\n"
                    f"Nmap scan results (JSON):\n{nmap_result}\n\n"
                    "Summarise the attack surface in bullet points. "
                    "Flag high-value services and potential entry points."
                )
            ),
        ]
        response = self.llm.invoke(messages)

        finding = {
            "phase": "recon",
            "target": state.target,
            "nmap_raw": nmap_result,
            "llm_analysis": response.content,
        }
        return {
            "tool_outputs": {"nmap": nmap_result},
            "findings": [finding],
            "current_step": "recon_complete",
        }

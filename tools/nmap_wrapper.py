"""
tools/nmap_wrapper.py
Wrapper around python-nmap that returns structured scan results
suitable for downstream LLM consumption.
"""
from __future__ import annotations

from typing import Any
import nmap

from tools.tool_base import BaseTool


class NmapTool(BaseTool):
    name = "nmap"
    description = (
        "Run an Nmap port scan against a target host or CIDR range. "
        "Returns open ports, services, versions, and OS guesses."
    )

    # Default arguments produce a service/version + OS detection scan.
    DEFAULT_ARGS = "-sT -sV -Pn --open -T4"

    def run(self, target: str, arguments: str = DEFAULT_ARGS) -> dict[str, Any]:
        """
        Parameters
        ----------
        target:    IP, hostname, or CIDR range (must be in authorised scope).
        arguments: nmap CLI flags (default: service/version + OS detection).

        Returns
        -------
        Structured dict with 'hosts' list, each entry containing open
        ports, service info, and OS matches.
        """
        scanner = nmap.PortScanner()
        scanner.scan(hosts=target, arguments=arguments)

        results: list[dict[str, Any]] = []
        for host in scanner.all_hosts():
            host_entry: dict[str, Any] = {
                "host": host,
                "hostname": scanner[host].hostname(),
                "state": scanner[host].state(),
                "os_matches": self._parse_os(scanner, host),
                "ports": [],
            }
            for proto in scanner[host].all_protocols():
                for port, port_data in scanner[host][proto].items():
                    host_entry["ports"].append(
                        {
                            "port": port,
                            "protocol": proto,
                            "state": port_data.get("state"),
                            "service": port_data.get("name"),
                            "product": port_data.get("product"),
                            "version": port_data.get("version"),
                            "extrainfo": port_data.get("extrainfo"),
                        }
                    )
            results.append(host_entry)

        return {"scan_args": arguments, "target": target, "hosts": results}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_os(scanner: nmap.PortScanner, host: str) -> list[dict[str, Any]]:
        try:
            matches = scanner[host]["osmatch"]
            return [
                {"name": m.get("name"), "accuracy": m.get("accuracy")}
                for m in matches[:3]  # top-3 guesses
            ]
        except (KeyError, TypeError):
            return []

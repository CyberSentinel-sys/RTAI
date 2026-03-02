"""
agents/osint_agent.py
OSINT Intelligence agent: consumes service/version data from the Nmap
scan results and uses the Tavily search API to gather CVEs, known
exploits, and official documentation for each discovered service.
Findings are written to RTAIState.osint_results for downstream use by
ExploitAgent, and a summary entry is appended to RTAIState.findings.
"""
from __future__ import annotations

import json
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage
from tavily import TavilyClient

from agents.base_agent import BaseAgent
from core.config import Config
from core.state import RTAIState


class OsintAgent(BaseAgent):
    role = "OSINT Intelligence Analyst"
    goal = (
        "Research discovered services and versions using open-source intelligence. "
        "Find CVEs, public exploits, and official documentation to enrich the "
        "exploitation analysis phase with verified, actionable intelligence."
    )

    # Maximum Tavily results per query — keeps token usage predictable
    _MAX_RESULTS = 5

    def run(self, state: RTAIState) -> dict[str, Any]:
        client = TavilyClient(api_key=Config.TAVILY_API_KEY)

        services = self._extract_services(state.tool_outputs.get("nmap", {}))
        if not services:
            return {
                "osint_results": [],
                "findings": [{"phase": "osint", "target": state.target,
                               "summary": "No services identified for OSINT research."}],
                "current_step": "osint_complete",
            }

        osint_results: list[dict[str, Any]] = []
        for svc in services:
            label = svc["label"]
            result_entry: dict[str, Any] = {
                "service": label,
                "port": svc["port"],
                "protocol": svc["protocol"],
                "cves": [],
                "exploits": [],
                "docs": [],
            }

            result_entry["cves"]    = self._search(client, f"{label} CVE vulnerability")
            result_entry["exploits"] = self._search(client, f"{label} known exploit proof of concept")
            result_entry["docs"]    = self._search(client, f"{label} official documentation changelog")

            osint_results.append(result_entry)

        # LLM synthesis — distil raw search results into analyst-grade notes
        synthesis = self._synthesise(state.target, osint_results)

        finding = {
            "phase": "osint",
            "target": state.target,
            "services_researched": [s["label"] for s in services],
            "llm_synthesis": synthesis,
        }

        return {
            "osint_results": osint_results,
            "findings": [finding],
            "current_step": "osint_complete",
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_services(nmap_data: dict[str, Any]) -> list[dict[str, str]]:
        """
        Pull unique (product, version) combos from Nmap output.
        Returns a deduplicated list of dicts with label, port, protocol.
        """
        seen: set[str] = set()
        services: list[dict[str, str]] = []

        for host in nmap_data.get("hosts", []):
            for port_info in host.get("ports", []):
                product = (port_info.get("product") or "").strip()
                version = (port_info.get("version") or "").strip()
                service = (port_info.get("service") or "").strip()

                # Build the most descriptive label available
                if product and version:
                    label = f"{product} {version}"
                elif product:
                    label = product
                elif service:
                    label = service
                else:
                    continue  # nothing useful to search for

                if label not in seen:
                    seen.add(label)
                    services.append({
                        "label": label,
                        "port": str(port_info.get("port", "")),
                        "protocol": port_info.get("protocol", "tcp"),
                    })

        return services

    def _search(self, client: TavilyClient, query: str) -> list[dict[str, str]]:
        """Run a single Tavily search and return a cleaned result list."""
        try:
            response = client.search(
                query=query,
                search_depth="advanced",
                max_results=self._MAX_RESULTS,
            )
            return [
                {
                    "title": r.get("title", ""),
                    "url": r.get("url", ""),
                    "snippet": r.get("content", "")[:400],
                }
                for r in response.get("results", [])
            ]
        except Exception as exc:  # noqa: BLE001
            return [{"error": str(exc)}]

    def _synthesise(self, target: str, osint_results: list[dict[str, Any]]) -> str:
        """Ask the LLM to distil the raw OSINT data into concise analyst notes."""
        messages = [
            SystemMessage(content=self._system_prompt()),
            HumanMessage(
                content=(
                    f"Target: {target}\n\n"
                    f"Raw OSINT data (JSON):\n{json.dumps(osint_results, indent=2)}\n\n"
                    "For each service, produce a concise analyst note with:\n"
                    "  - Most critical CVEs found (include CVSS score if available)\n"
                    "  - Most viable public exploits or PoCs\n"
                    "  - Any relevant version-specific security advisories\n"
                    "Flag any Critical or High severity items prominently. "
                    "Be precise and cite sources (URLs) where available."
                )
            ),
        ]
        response = self.llm.invoke(messages)
        return response.content

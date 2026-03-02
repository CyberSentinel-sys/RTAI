"""
agents/osint_agent.py
OSINT Intelligence agent: extracts service names and versions from the
recon finding in RTAIState.findings, runs a single focused Tavily
search per service ("[Service] [Version] known vulnerabilities exploits"),
then asks the LLM to summarise the top 3 high-risk items (CVEs, PoCs,
default credentials) per service and appends them to state.findings.
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
        "Using open-source intelligence, find the top 3 high-risk vulnerabilities "
        "(CVEs, public PoCs, or default credentials) for every service discovered "
        "during reconnaissance and deliver them as structured, actionable findings."
    )

    _MAX_RESULTS = 5

    def run(self, state: RTAIState) -> dict[str, Any]:
        client = TavilyClient(api_key=Config.TAVILY_API_KEY)

        services = self._extract_services(state)
        if not services:
            return {
                "osint_results": [],
                "findings": [{
                    "phase": "osint",
                    "target": state.target,
                    "top_3_risks": [],
                    "summary": "No services identified for OSINT research.",
                }],
                "current_step": "osint_complete",
            }

        osint_results: list[dict[str, Any]] = []
        for svc in services:
            label = svc["label"]
            raw_hits = self._search(
                client,
                query=f"{label} known vulnerabilities exploits",
            )
            osint_results.append({
                "service": label,
                "port": svc["port"],
                "protocol": svc["protocol"],
                "raw_hits": raw_hits,
            })

        top_3_risks, synthesis = self._synthesise(state.target, osint_results)

        finding = {
            "phase": "osint",
            "target": state.target,
            "services_researched": [s["label"] for s in services],
            "top_3_risks": top_3_risks,
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
    def _extract_services(state: RTAIState) -> list[dict[str, str]]:
        """
        Extract unique service/version labels.
        Primary source: nmap_raw inside the recon finding (RTAIState.findings).
        Fallback:       state.tool_outputs["nmap"] (set by ReconAgent).
        """
        # Prefer the structured nmap data stored in findings by ReconAgent
        recon_finding = next(
            (f for f in state.findings if f.get("phase") == "recon"), {}
        )
        nmap_data: dict[str, Any] = (
            recon_finding.get("nmap_raw")
            or state.tool_outputs.get("nmap")
            or {}
        )

        seen: set[str] = set()
        services: list[dict[str, str]] = []

        for host in nmap_data.get("hosts", []):
            for port_info in host.get("ports", []):
                product = (port_info.get("product") or "").strip()
                version = (port_info.get("version") or "").strip()
                service = (port_info.get("service") or "").strip()

                if product and version:
                    label = f"{product} {version}"
                elif product:
                    label = product
                elif service:
                    label = service
                else:
                    continue

                if label not in seen:
                    seen.add(label)
                    services.append({
                        "label": label,
                        "port": str(port_info.get("port", "")),
                        "protocol": port_info.get("protocol", "tcp"),
                    })

        return services

    def _search(self, client: TavilyClient, query: str) -> list[dict[str, str]]:
        """Run a single Tavily search and return cleaned results."""
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

    def _synthesise(
        self,
        target: str,
        osint_results: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], str]:
        """
        Ask the LLM to extract the top 3 high-risk findings across all
        services and return them as a structured list plus a prose summary.
        """
        messages = [
            SystemMessage(content=self._system_prompt()),
            HumanMessage(
                content=(
                    f"Target: {target}\n\n"
                    f"Raw OSINT search results (JSON):\n"
                    f"{json.dumps(osint_results, indent=2)}\n\n"
                    "Identify the TOP 3 highest-risk findings across ALL services. "
                    "Focus on: CVEs with high/critical CVSS scores, public PoCs or "
                    "Metasploit modules, and known default credentials.\n\n"
                    "Return your answer in this EXACT JSON format (no markdown fences):\n"
                    "{\n"
                    '  "top_3_risks": [\n'
                    "    {\n"
                    '      "rank": 1,\n'
                    '      "service": "<service and version>",\n'
                    '      "type": "CVE | PoC | DefaultCreds | Other",\n'
                    '      "identifier": "<CVE-XXXX-XXXX or tool name>",\n'
                    '      "cvss": "<score or N/A>",\n'
                    '      "description": "<one sentence>",\n'
                    '      "source_url": "<url or N/A>"\n'
                    "    }\n"
                    "  ],\n"
                    '  "summary": "<3-5 sentence analyst summary of the OSINT phase>"\n'
                    "}"
                )
            ),
        ]
        response = self.llm.invoke(messages)

        # Parse the structured JSON response from the LLM
        try:
            parsed = json.loads(response.content)
            top_3 = parsed.get("top_3_risks", [])
            summary = parsed.get("summary", response.content)
        except (json.JSONDecodeError, AttributeError):
            # If the LLM doesn't return valid JSON, store raw content
            top_3 = []
            summary = response.content

        return top_3, summary

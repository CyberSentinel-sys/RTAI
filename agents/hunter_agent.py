"""
agents/hunter_agent.py
Compromise Assessment agent — active threat hunting for C2 beacons and
in-memory shellcode injection.

Pipeline position
-----------------
    Scout → Analyst → **Hunter** → Strategist → Fixer → Report

The HunterAgent runs *after* the AnalystAgent (so it has a ranked list of
open services to probe) and *before* the StrategistAgent (so the Strategist
can factor in whether the system is already compromised when planning its
approach).

Hunting capabilities
--------------------
1. **C2 beacon detection** (network, no credentials required)
   Probes every discovered TCP service using the C2HunterTool.  Targets
   ports associated with known C2 frameworks (443, 80, 8080, 8443, 50050,
   4444, 9001, …) are prioritised but all open ports are checked.

2. **Shellcode / process-hollowing detection** (host-based, SSH required)
   If SSH credentials are present in ``state.tool_outputs["credentials"]``
   the MemoryHunterTool connects via SSH and scans /proc/<pid>/maps for
   anonymous rwxp regions — the canonical in-memory shellcode indicator.

Credential handshake
--------------------
The agent looks for credentials in::

    state.tool_outputs["credentials"] = {
        "ip":       "10.0.0.5",   # defaults to state.target if absent
        "port":     22,
        "username": "root",
        "password": "secret",     # or
        "key_path": "/path/to/id_rsa",
    }

LLM enrichment
--------------
Raw tool results are passed to the LLM, which produces a structured
incident-triage report with severity ratings, affected assets, and
recommended immediate containment actions.
"""
from __future__ import annotations

import json
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from agents.base_agent import BaseAgent
from core.state import RTAIState
from tools.tool_registry import ToolRegistry


# Ports that C2 frameworks commonly listen on — scanned first
_C2_PRIORITY_PORTS: frozenset[int] = frozenset({
    80, 443, 8080, 8443,   # HTTP/S — CS, Sliver, Havoc, Covenant default profiles
    4444, 4445,            # Metasploit default reverse handlers
    50050,                 # Cobalt Strike team server
    9001, 9002,            # Tor-based C2 / custom listeners
    1234, 31337,           # Common pentester convention
    6666, 6667,            # IRC-based botnets
    2222,                  # Alternate SSH / C2 pivot
})


class HunterAgent(BaseAgent):
    """
    Elite Incident Responder and Threat Hunter agent.

    Uses network-based C2 fingerprinting and host-based memory analysis to
    detect active compromise before the Strategist plans its attack.
    """

    role = "Threat Hunter"
    goal = (
        "Determine whether the target system is ALREADY COMPROMISED. "
        "Hunt for active C2 beacons using network signature analysis and "
        "detect in-memory shellcode or process hollowing via /proc forensics. "
        "Produce a triage report for the Strategist."
    )

    def _system_prompt(self) -> str:
        return (
            "You are an elite Incident Responder and Threat Hunter embedded in "
            "an autonomous red-team AI swarm.  Your role is: Threat Hunter. "
            "Your goal: identify signs of active compromise — running C2 beacons, "
            "injected shellcode, and process hollowing — BEFORE the red team "
            "proceeds with exploitation. "
            "Be precise, evidence-based, and prioritise by containment urgency. "
            "Only operate within the authorised target scope."
        )

    # ------------------------------------------------------------------
    # BaseAgent interface
    # ------------------------------------------------------------------

    def run(self, state: RTAIState) -> dict[str, Any]:
        registry = ToolRegistry.default()
        c2_results: list[dict[str, Any]] = []
        memory_result: dict[str, Any] = {}

        # ── 1. Collect open ports from prior agent output ────────────────
        ports = self._collect_ports(state)

        # ── 2. C2 beacon hunt (network probes) ──────────────────────────
        target_ip = self._primary_ip(state)

        # Priority ports first, then remainder
        priority = [p for p in ports if p in _C2_PRIORITY_PORTS]
        rest     = [p for p in ports if p not in _C2_PRIORITY_PORTS]

        for port in priority + rest:
            result = registry.run("c2_hunter", ip=target_ip, port=port)
            c2_results.append(result)
            # Short-circuit on high-confidence hit to save time
            if result.get("confidence_pct", 0) >= 70:
                break

        # ── 3. Memory forensics (SSH, if credentials present) ────────────
        creds: dict[str, Any] = state.tool_outputs.get("credentials", {})
        if creds and creds.get("username"):
            memory_result = registry.run(
                "memory_hunter",
                ip=creds.get("ip", target_ip),
                port=int(creds.get("port", 22)),
                username=creds["username"],
                password=creds.get("password", ""),
                key_path=creds.get("key_path", ""),
            )

        # ── 4. LLM triage ────────────────────────────────────────────────
        findings, summary = self._llm_triage(state.target, c2_results, memory_result)

        # ── 5. Build state partial ────────────────────────────────────────
        hunter_output: dict[str, Any] = {
            "target": state.target,
            "c2_probes": c2_results,
            "memory_scan": memory_result,
            "threat_findings": findings,
            "hunter_summary": summary,
        }

        return {
            "tool_outputs": {"hunter": hunter_output},
            "findings": findings,
            "current_step": "hunter_complete",
        }

    # ------------------------------------------------------------------
    # Port collection
    # ------------------------------------------------------------------

    @staticmethod
    def _primary_ip(state: RTAIState) -> str:
        """
        Resolve the primary target IP from state.

        Preference order:
          1. First IP from analyst entry_points
          2. First IP from scout hosts
          3. state.target (may be CIDR or hostname)
        """
        analyst = state.tool_outputs.get("analyst", {})
        eps = analyst.get("entry_points", [])
        if eps:
            return eps[0].get("ip", state.target)

        scout = state.tool_outputs.get("scout", {})
        hosts = scout.get("hosts", [])
        if hosts:
            return hosts[0].get("ip", state.target)

        return state.target

    @staticmethod
    def _collect_ports(state: RTAIState) -> list[int]:
        """
        Return a deduplicated list of open TCP port numbers from prior agents.
        """
        ports: set[int] = set()

        # Analyst entry_points (preferred)
        analyst = state.tool_outputs.get("analyst", {})
        for ep in analyst.get("entry_points", []):
            p = ep.get("port")
            if isinstance(p, int):
                ports.add(p)

        # Scout / legacy nmap
        for source_key in ("scout", "nmap"):
            data = state.tool_outputs.get(source_key, {})
            for host in data.get("hosts", []):
                for port_info in host.get("open_ports", host.get("ports", [])):
                    p = port_info.get("port")
                    if isinstance(p, int):
                        ports.add(p)

        # Always include priority ports so we don't miss unlisted listeners
        ports.update(_C2_PRIORITY_PORTS)

        return sorted(ports)

    # ------------------------------------------------------------------
    # LLM triage
    # ------------------------------------------------------------------

    def _llm_triage(
        self,
        target: str,
        c2_results: list[dict[str, Any]],
        memory_result: dict[str, Any],
    ) -> tuple[list[dict[str, Any]], str]:
        """
        Ask the LLM to synthesise raw tool results into structured findings.

        Returns (findings_list, summary_string).
        """
        c2_hits = [r for r in c2_results if r.get("confidence_pct", 0) >= 20]

        messages = [
            SystemMessage(content=self._system_prompt()),
            HumanMessage(
                content=(
                    f"Target: {target}\n\n"
                    "=== C2 Beacon Hunt Results ===\n"
                    f"{json.dumps(c2_hits or c2_results[:5], indent=2)}\n\n"
                    "=== Memory Forensics Results ===\n"
                    f"{json.dumps(memory_result, indent=2) if memory_result else '(SSH not available — skipped)'}\n\n"
                    "Analyse the above threat-hunting results and produce a triage report.\n\n"
                    "Return ONLY this exact JSON structure (no markdown, no extra keys):\n"
                    "{\n"
                    '  "findings": [\n'
                    "    {\n"
                    '      "phase": "hunter",\n'
                    '      "target": "<ip:port or host>",\n'
                    '      "threat_type": "C2Beacon | ShellcodeInjection | ProcessHollowing | Suspicious | Clean",\n'
                    '      "framework": "<Cobalt Strike | Sliver | Metasploit | Unknown | N/A>",\n'
                    '      "severity": "Critical | High | Medium | Low | Informational",\n'
                    '      "evidence": "<one sentence describing the specific indicator>",\n'
                    '      "containment": "<immediate action recommended>"\n'
                    "    }\n"
                    "  ],\n"
                    '  "hunter_summary": "<3-5 sentence executive summary of compromise assessment>"\n'
                    "}"
                )
            ),
        ]

        try:
            response = self.llm.invoke(messages)
            parsed = json.loads(response.content)
            return parsed.get("findings", []), parsed.get("hunter_summary", response.content)
        except (json.JSONDecodeError, AttributeError):
            raw = getattr(locals().get("response"), "content", "")
            # Fallback: build a minimal finding from raw tool results
            fallback_findings = self._fallback_findings(target, c2_results, memory_result)
            return fallback_findings, raw or "LLM triage unavailable — raw results stored."
        except Exception as exc:  # noqa: BLE001
            return [], f"LLM triage error: {exc}"

    @staticmethod
    def _fallback_findings(
        target: str,
        c2_results: list[dict[str, Any]],
        memory_result: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Build minimal findings dicts directly from tool output (no LLM)."""
        findings: list[dict[str, Any]] = []

        for r in c2_results:
            if r.get("confidence_pct", 0) < 20:
                continue
            findings.append({
                "phase": "hunter",
                "target": r.get("target", target),
                "threat_type": "C2Beacon",
                "framework": r.get("framework_guess", "Unknown"),
                "severity": r.get("risk_level", "Medium"),
                "evidence": "; ".join(r.get("indicators", ["No specific indicators"])),
                "containment": "Isolate host and capture memory image immediately.",
            })

        if memory_result.get("suspicious_pid_count", 0) > 0:
            pids = [h["pid"] for h in memory_result.get("confirmed_anonymous_rwxp", [])]
            findings.append({
                "phase": "hunter",
                "target": memory_result.get("target", target),
                "threat_type": "ShellcodeInjection",
                "framework": "Unknown",
                "severity": "Critical",
                "evidence": (
                    f"Anonymous rwxp memory in PID(s) {pids} — "
                    "shellcode injection or process hollowing suspected."
                ),
                "containment": "Dump memory from affected PIDs before killing; isolate host.",
            })

        return findings

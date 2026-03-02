"""
agents/recon_agent.py
Reconnaissance agent: runs Nmap against the target and uses the LLM
to interpret the results and identify interesting attack surface.
"""
from __future__ import annotations

from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from agents.base_agent import BaseAgent
from core.state import RTAIState
from tools.tool_registry import ToolRegistry


class ReconAgent(BaseAgent):
    role = "Reconnaissance Specialist"
    goal = "Enumerate hosts, open ports, running services, and OS information."

    def run(self, state: RTAIState) -> dict[str, Any]:
        registry = ToolRegistry.default()

        # 1. Run Nmap scan
        nmap_result = registry.run("nmap", target=state.target)

        # 2. Ask the LLM to interpret the scan output
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

"""
agents/remediation_agent.py
Remediation agent: for every attack vector produced by ExploitAgent,
generates a concrete, actionable remediation — patch commands, config
changes, code snippets, and a verification step.

Output is structured JSON so ReportAgent can render it deterministically
without re-parsing prose. Each remediation is tied 1-to-1 to a specific
exploit finding by its risk_level and affected service.
"""
from __future__ import annotations

import json
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from agents.base_agent import BaseAgent
from core.state import RTAIState


# Canonical risk ordering for sorting
_RISK_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class RemediationAgent(BaseAgent):
    role = "Remediation Engineer"
    goal = (
        "For every confirmed attack vector, produce step-by-step remediation "
        "instructions including shell commands, configuration changes, and "
        "code patches so a system administrator can immediately act on the findings."
    )

    def run(self, state: RTAIState) -> dict[str, Any]:
        exploit_finding = next(
            (f for f in state.findings if f.get("phase") == "exploit_analysis"), {}
        )
        osint_finding = next(
            (f for f in state.findings if f.get("phase") == "osint"), {}
        )

        attack_vectors  = exploit_finding.get("attack_vectors", "")
        top_3_risks     = osint_finding.get("top_3_risks", [])

        if not attack_vectors:
            return {
                "remediations": [],
                "findings": [{
                    "phase": "remediation",
                    "target": state.target,
                    "remediations": [],
                    "summary": "No attack vectors to remediate.",
                }],
                "current_step": "remediation_complete",
            }

        remediations = self._generate_remediations(
            state.target, attack_vectors, top_3_risks
        )

        # Sort Critical → High → Medium → Low
        remediations.sort(
            key=lambda r: _RISK_RANK.get(r.get("risk_level", "").lower(), 99)
        )

        finding = {
            "phase": "remediation",
            "target": state.target,
            "remediations": remediations,
        }

        return {
            "remediations": remediations,
            "findings": [finding],
            "current_step": "remediation_complete",
        }

    # -------------------------------------------------------------------------

    def _generate_remediations(
        self,
        target: str,
        attack_vectors: str,
        top_3_risks: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:

        messages = [
            SystemMessage(content=self._system_prompt()),
            HumanMessage(
                content=(
                    f"Target: {target}\n\n"
                    f"Attack vectors identified by ExploitAgent:\n{attack_vectors}\n\n"
                    f"OSINT top-3 risks (CVEs / PoCs / default creds):\n"
                    f"{json.dumps(top_3_risks, indent=2)}\n\n"
                    "For EACH numbered attack vector above, produce a remediation entry.\n"
                    "Return ONLY a valid JSON array (no markdown fences) where every "
                    "element matches this schema exactly:\n"
                    "{\n"
                    '  "id": <integer matching the attack vector number>,\n'
                    '  "title": "<short imperative title, e.g. Patch Apache CVE-2023-25690>",\n'
                    '  "risk_level": "<Critical | High | Medium | Low>",\n'
                    '  "service": "<affected service and version>",\n'
                    '  "cve": "<CVE-XXXX-XXXX or N/A>",\n'
                    '  "steps": ["<step 1>", "<step 2>", ...],\n'
                    '  "code_snippet": "<shell commands or config block, or null>",\n'
                    '  "verification": "<single command or test to confirm fix applied>"\n'
                    "}\n\n"
                    "Rules:\n"
                    "- steps must be specific shell commands or config directives, "
                    "  not vague advice like 'update your software'\n"
                    "- code_snippet should be copy-paste ready (bash, yaml, or config syntax)\n"
                    "- verification must be a concrete, runnable check\n"
                    "- risk_level must match the level assigned by ExploitAgent\n"
                    "- If a CVE has an official vendor advisory, reference it in steps"
                )
            ),
        ]
        response = self.llm.invoke(messages)

        try:
            return json.loads(response.content)
        except (json.JSONDecodeError, ValueError):
            # Graceful fallback: wrap raw content as a single unstructured entry
            return [{
                "id": 0,
                "title": "Remediation guidance (unstructured)",
                "risk_level": "Unknown",
                "service": "N/A",
                "cve": "N/A",
                "steps": [response.content],
                "code_snippet": None,
                "verification": "N/A",
            }]

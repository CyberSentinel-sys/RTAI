"""
agents/swarm_controller.py
Swarm orchestrator: linear pipeline of specialised agents.

Default pipeline
----------------
    Scout → Analyst → Strategist → Fixer

Each agent receives the full RTAIState, enriches it, and passes the updated
state to the next stage.  Every agent's start/complete events are written
to ``RTAIState.action_log`` automatically via ``BaseAgent.execute()``.

Adding a new stage
------------------
Option A – extend the default pipeline at runtime::

    SwarmController.PIPELINE.append(MyNewAgent)

Option B – subclass with a custom pipeline::

    class MySwarm(SwarmController):
        PIPELINE = [ScoutAgent, AnalystAgent, MyNewAgent, FixerAgent]

Option C – pass a pipeline at construction time::

    ctrl = SwarmController(pipeline=[ScoutAgent, FixerAgent])
"""
from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from agents.base_agent import BaseAgent, _merge_partial
from core.state import RTAIState
from tools.tool_registry import ToolRegistry


# ---------------------------------------------------------------------------
# Swarm agents
# ---------------------------------------------------------------------------

class ScoutAgent(BaseAgent):
    """
    Stage 1 – gather raw intelligence.

    Runs an Nmap scan against the target and asks the LLM to summarise the
    attack surface.  Results are stored in ``tool_outputs["nmap"]`` and a
    structured entry is appended to ``findings``.
    """

    role = "Scout"
    goal = (
        "Perform rapid target reconnaissance. "
        "Enumerate open ports, running services, and OS fingerprints."
    )

    def run(self, state: RTAIState) -> dict[str, Any]:
        registry = ToolRegistry.default()
        nmap_result = registry.run("nmap", target=state.target)

        messages = [
            SystemMessage(content=self._system_prompt()),
            HumanMessage(
                content=(
                    f"Target: {state.target}\n\n"
                    f"Nmap scan results:\n{json.dumps(nmap_result, indent=2)}\n\n"
                    "List every open port and service. "
                    "Flag any service with high exploitation potential and explain why."
                )
            ),
        ]
        response = self.llm.invoke(messages)

        return {
            "tool_outputs": {"nmap": nmap_result},
            "findings": [
                {
                    "phase": "scout",
                    "target": state.target,
                    "nmap_raw": nmap_result,
                    "surface_summary": response.content,
                }
            ],
            "current_step": "scout_complete",
        }


class AnalystAgent(BaseAgent):
    """
    Stage 2 – identify and rank attack vectors.

    Reads Scout's nmap data and prior findings, then asks the LLM to
    enumerate exploitable vulnerabilities with risk ratings.
    """

    role = "Analyst"
    goal = (
        "Identify exploitable vulnerabilities from Scout's recon data. "
        "Assign a risk rating (Critical / High / Medium / Low) to each."
    )

    def run(self, state: RTAIState) -> dict[str, Any]:
        nmap_data = state.tool_outputs.get("nmap", {})
        prior = state.findings

        messages = [
            SystemMessage(content=self._system_prompt()),
            HumanMessage(
                content=(
                    f"Target: {state.target}\n\n"
                    f"Nmap data:\n{json.dumps(nmap_data, indent=2)}\n\n"
                    f"Scout findings:\n{json.dumps(prior, indent=2)}\n\n"
                    "Identify all potential attack vectors. "
                    "For each, provide:\n"
                    "  • Risk rating (Critical / High / Medium / Low)\n"
                    "  • Affected service and port\n"
                    "  • Exploitation likelihood and brief justification\n"
                    "Return as a numbered list ordered by risk (highest first)."
                )
            ),
        ]
        response = self.llm.invoke(messages)

        return {
            "findings": [
                {
                    "phase": "analyst",
                    "target": state.target,
                    "attack_vectors": response.content,
                }
            ],
            "current_step": "analyst_complete",
        }


class StrategistAgent(BaseAgent):
    """
    Stage 3 – design the attack plan.

    Synthesises Analyst's vulnerability list into an ordered, low-noise-first
    attack strategy with fallback options at each step.
    """

    role = "Strategist"
    goal = (
        "Design an ordered, step-by-step attack strategy from the Analyst's "
        "vulnerability ranking.  Minimise noise; maximise impact."
    )

    def run(self, state: RTAIState) -> dict[str, Any]:
        findings_text = json.dumps(state.findings, indent=2)

        messages = [
            SystemMessage(content=self._system_prompt()),
            HumanMessage(
                content=(
                    f"Target: {state.target}\n\n"
                    f"Analyst findings:\n{findings_text}\n\n"
                    "Design a step-by-step attack strategy. "
                    "Order steps from lowest-noise to highest-impact. "
                    "For each step include:\n"
                    "  • Objective\n"
                    "  • Technique / tool\n"
                    "  • Expected outcome\n"
                    "  • Fallback if the step fails\n"
                )
            ),
        ]
        response = self.llm.invoke(messages)

        return {
            "tool_outputs": {"strategy": response.content},
            "findings": [
                {
                    "phase": "strategist",
                    "target": state.target,
                    "attack_plan": response.content,
                }
            ],
            "current_step": "strategist_complete",
        }


class FixerAgent(BaseAgent):
    """
    Stage 4 – produce remediation guidance.

    For every vulnerability surfaced by the Analyst and every step in the
    Strategist's plan, the Fixer produces immediate mitigations, long-term
    fixes, and detection/monitoring recommendations.
    """

    role = "Fixer"
    goal = (
        "Produce actionable remediation recommendations for every identified "
        "vulnerability.  Cover immediate mitigation, long-term fixes, and "
        "detection/monitoring."
    )

    def run(self, state: RTAIState) -> dict[str, Any]:
        findings_text = json.dumps(state.findings, indent=2)
        strategy = state.tool_outputs.get("strategy", "(no strategy produced)")

        messages = [
            SystemMessage(content=self._system_prompt()),
            HumanMessage(
                content=(
                    f"Target: {state.target}\n\n"
                    f"Findings:\n{findings_text}\n\n"
                    f"Attack strategy:\n{strategy}\n\n"
                    "For every identified vulnerability, provide:\n"
                    "  1. Immediate mitigation (can be applied today)\n"
                    "  2. Long-term remediation (structural / architectural fix)\n"
                    "  3. Detection / monitoring recommendation\n"
                    "Label each item with its severity: Critical / High / Medium / Low."
                )
            ),
        ]
        response = self.llm.invoke(messages)

        return {
            "remediations": [
                {
                    "phase": "fixer",
                    "target": state.target,
                    "recommendations": response.content,
                }
            ],
            "current_step": "fixer_complete",
            "finished": True,
        }


# ---------------------------------------------------------------------------
# Swarm controller
# ---------------------------------------------------------------------------

class SwarmController:
    """
    Linear swarm pipeline controller.

    Agents are executed in ``PIPELINE`` order.  Each agent's ``execute()``
    method receives the full ``RTAIState``, merges its output back in, and
    logs start/complete events to ``state.action_log`` before passing state
    to the next stage.

    Customisation
    -------------
    *Append* a new agent class::

        SwarmController.PIPELINE.append(MyNewAgent)

    *Subclass* with a custom pipeline::

        class MySwarm(SwarmController):
            PIPELINE = [ScoutAgent, MyMidAgent, FixerAgent]

    *Inject* at construction time::

        ctrl = SwarmController(pipeline=[ScoutAgent, FixerAgent])
    """

    #: Default ordered pipeline — uses the full standalone agent implementations.
    #: The simplified ScoutAgent / AnalystAgent / StrategistAgent / FixerAgent
    #: classes defined above in this module are kept as lightweight demos and
    #: are not used by default.
    PIPELINE: list[type[BaseAgent]] = []  # populated after imports below

    def __init__(self, pipeline: list[type[BaseAgent]] | None = None) -> None:
        """
        Parameters
        ----------
        pipeline:
            Override the class-level ``PIPELINE`` for this instance only.
            Pass ``None`` (default) to use the class-level list.
        """
        self._pipeline: list[type[BaseAgent]] = pipeline if pipeline is not None else self.PIPELINE

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, target: str, engagement_name: str = "swarm_engagement") -> RTAIState:
        """
        Execute every stage in the pipeline sequentially.

        Parameters
        ----------
        target:
            IP, hostname, or CIDR range to test (must be in authorised scope).
        engagement_name:
            Label used in reports and log filenames.

        Returns
        -------
        Final ``RTAIState`` after all agents have completed.  Inspect
        ``state.action_log`` for the full execution trace.
        """
        state = RTAIState(target=target, engagement_name=engagement_name)

        for AgentClass in self._pipeline:
            agent = AgentClass()
            state = agent.execute(state)

        # After all agents complete, gate execution behind human approval
        # and notify the operator via Telegram (if configured).
        self._request_approval(state)

        return state

    # ------------------------------------------------------------------
    # Approval gate + Telegram notification
    # ------------------------------------------------------------------

    def _request_approval(self, state: RTAIState) -> None:
        """
        Set ``state.awaiting_approval = True``, advance the swarm status to
        ``AWAITING_APPROVAL``, and send a Telegram alert so the operator
        knows to visit the Dashboard and approve before fixes run.

        Telegram is optional — the gate still activates even if the message
        cannot be delivered (no token, network unreachable, etc.).
        """
        state.awaiting_approval = True
        state.current_step = "AWAITING_APPROVAL"
        self._send_telegram_approval(state)

    @staticmethod
    def _send_telegram_approval(state: RTAIState) -> None:
        """
        POST a Markdown-formatted message to a Telegram Bot.

        Required environment variables
        -------------------------------
        ``TELEGRAM_BOT_TOKEN``  — token from @BotFather
        ``TELEGRAM_CHAT_ID``    — recipient chat / channel / group ID

        Silently skips if either variable is absent or the HTTP call fails.
        """
        token   = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        chat_id = os.getenv("TELEGRAM_CHAT_ID",   "").strip()
        if not token or not chat_id:
            return

        fixer       = state.tool_outputs.get("fixer", {})
        total       = fixer.get("total_fixes", 0)
        critical    = fixer.get("critical_count", 0)
        high        = fixer.get("high_count", 0)
        medium      = fixer.get("medium_count", 0)
        low         = fixer.get("low_count", 0)
        disruptive  = fixer.get("disruptive_count", 0)

        lines = [
            f"⚠️ Vulnerabilities Found on {state.target}. "
            "Review the Battle Plan in the Dashboard and click APPROVE to execute fixes.",
            "",
            f"📋 Engagement: `{state.engagement_name}`",
            f"📊 *{total}* fix(es) — Critical: {critical} | High: {high} "
            f"| Medium: {medium} | Low: {low}",
        ]

        if disruptive:
            disruptive_fixes = [
                f for f in fixer.get("fixes", [])
                if f.get("potentially_disruptive")
            ]
            lines += [
                "",
                f"⚠️ *{disruptive} Potentially Disruptive fix(es) require review:*",
            ]
            for df in disruptive_fixes[:5]:
                fid     = df.get("fix_id", "?")
                title   = df.get("title", "Untitled")[:50]
                reasons = "; ".join(df.get("disruption_reasons", []))[:80]
                lines.append(f"   `{fid}` {title}")
                lines.append(f"         _{reasons}_")

        text = "\n".join(lines)
        url  = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = urllib.parse.urlencode({
            "chat_id":    chat_id,
            "text":       text,
            "parse_mode": "Markdown",
        }).encode()

        try:
            req = urllib.request.Request(url, data=payload, method="POST")
            urllib.request.urlopen(req, timeout=10)
        except Exception:  # noqa: BLE001
            pass  # Non-fatal — approval gate is already active in state

    # ------------------------------------------------------------------
    # Introspection helpers
    # ------------------------------------------------------------------

    def pipeline_summary(self) -> list[dict[str, str]]:
        """Return a list of ``{role, goal}`` dicts describing the pipeline."""
        return [
            {"role": cls.role, "goal": cls.goal}
            for cls in self._pipeline
        ]


# ---------------------------------------------------------------------------
# Wire the default PIPELINE to the full standalone agent implementations.
# Imported here (after SwarmController is defined) to avoid circular imports.
# ---------------------------------------------------------------------------

from agents.scout_agent      import ScoutAgent      as _Scout       # noqa: E402
from agents.analyst_agent    import AnalystAgent    as _Analyst     # noqa: E402
from agents.strategist_agent import StrategistAgent as _Strategist  # noqa: E402
from agents.fixer_agent      import FixerAgent      as _Fixer       # noqa: E402

SwarmController.PIPELINE = [_Scout, _Analyst, _Strategist, _Fixer]

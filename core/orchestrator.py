"""
core/orchestrator.py
LangGraph-based orchestrator (legacy entry point).

Pipeline (strictly linear):
    START ──► scout ──► analyst ──► hunter ──► strategist ──► fixer ──► report ──► END

For new integrations prefer SwarmController (agents/swarm_controller.py) which
provides the approval gate, Telegram notifications, and a hot-swappable PIPELINE
list.  This module is retained for CLI (main.py) compatibility.
"""
from __future__ import annotations

from langgraph.graph import StateGraph, END

from core.config import Config
from core.state import RTAIState
from agents.scout_agent      import ScoutAgent
from agents.analyst_agent    import AnalystAgent
from agents.hunter_agent     import HunterAgent
from agents.strategist_agent import StrategistAgent
from agents.fixer_agent      import FixerAgent
from agents.report_agent     import ReportAgent


# ---------------------------------------------------------------------------
# Node wrappers
# ---------------------------------------------------------------------------

def scout_node(state: RTAIState) -> dict:
    return ScoutAgent().run(state)


def analyst_node(state: RTAIState) -> dict:
    return AnalystAgent().run(state)


def hunter_node(state: RTAIState) -> dict:
    return HunterAgent().run(state)


def strategist_node(state: RTAIState) -> dict:
    return StrategistAgent().run(state)


def fixer_node(state: RTAIState) -> dict:
    return FixerAgent().run(state)


def report_node(state: RTAIState) -> dict:
    return ReportAgent().run(state)


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------

class Orchestrator:
    def __init__(self) -> None:
        Config.validate()
        self._graph = self._build_graph()

    def _build_graph(self) -> StateGraph:
        builder = StateGraph(RTAIState)

        builder.add_node("scout",       scout_node)
        builder.add_node("analyst",     analyst_node)
        builder.add_node("hunter",      hunter_node)
        builder.add_node("strategist",  strategist_node)
        builder.add_node("fixer",       fixer_node)
        builder.add_node("report",      report_node)

        builder.set_entry_point("scout")

        # Strictly linear — every engagement passes through all six stages
        builder.add_edge("scout",      "analyst")
        builder.add_edge("analyst",    "hunter")      # ← NEW
        builder.add_edge("hunter",     "strategist")  # ← NEW
        builder.add_edge("strategist", "fixer")
        builder.add_edge("fixer",      "report")
        builder.add_edge("report",     END)

        return builder.compile()

    def run(self, target: str, engagement_name: str = "") -> RTAIState:
        initial = RTAIState(
            target=target,
            engagement_name=engagement_name or Config.ENGAGEMENT_NAME,
        )
        final = self._graph.invoke(initial)
        return RTAIState(**final)

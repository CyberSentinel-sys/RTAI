"""
core/orchestrator.py
LangGraph-based orchestrator that routes between ReconAgent, OsintAgent,
ExploitAgent, and ReportAgent based on engagement state.

Pipeline:
    recon ──► osint ──► exploit ──► report
      └─────────────────────────────────┘  (fallback if no hosts found)
"""
from __future__ import annotations

from langgraph.graph import StateGraph, END

from core.config import Config
from core.state import RTAIState
from agents.recon_agent import ReconAgent
from agents.osint_agent import OsintAgent
from agents.exploit_agent import ExploitAgent
from agents.report_agent import ReportAgent


# ---------------------------------------------------------------------------
# Node wrappers
# ---------------------------------------------------------------------------

def recon_node(state: RTAIState) -> dict:
    return ReconAgent().run(state)


def osint_node(state: RTAIState) -> dict:
    return OsintAgent().run(state)


def exploit_node(state: RTAIState) -> dict:
    return ExploitAgent().run(state)


def report_node(state: RTAIState) -> dict:
    return ReportAgent().run(state)


# ---------------------------------------------------------------------------
# Routing logic
# ---------------------------------------------------------------------------

def route_after_recon(state: RTAIState) -> str:
    """Route to OSINT if hosts were discovered, otherwise skip to report."""
    if state.finished:
        return "report"
    if state.tool_outputs.get("nmap", {}).get("hosts"):
        return "osint"
    return "report"


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------

class Orchestrator:
    def __init__(self) -> None:
        Config.validate()
        self._graph = self._build_graph()

    def _build_graph(self) -> StateGraph:
        builder = StateGraph(RTAIState)

        builder.add_node("recon", recon_node)
        builder.add_node("osint", osint_node)
        builder.add_node("exploit", exploit_node)
        builder.add_node("report", report_node)

        builder.set_entry_point("recon")

        builder.add_conditional_edges(
            "recon",
            route_after_recon,
            {"osint": "osint", "report": "report"},
        )
        # After OSINT always proceed to exploitation analysis
        builder.add_edge("osint", "exploit")
        # After exploitation analysis always proceed to report
        builder.add_edge("exploit", "report")
        builder.add_edge("report", END)

        return builder.compile()

    def run(self, target: str, engagement_name: str = "") -> RTAIState:
        initial = RTAIState(
            target=target,
            engagement_name=engagement_name or Config.ENGAGEMENT_NAME,
        )
        final = self._graph.invoke(initial)
        return RTAIState(**final)

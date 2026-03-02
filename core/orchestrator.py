"""
core/orchestrator.py
LangGraph-based orchestrator that routes between ReconAgent,
ExploitAgent, and ReportAgent based on engagement state.
"""
from __future__ import annotations

from langgraph.graph import StateGraph, END

from core.config import Config
from core.state import RTAIState
from agents.recon_agent import ReconAgent
from agents.exploit_agent import ExploitAgent
from agents.report_agent import ReportAgent


# ---------------------------------------------------------------------------
# Node wrappers
# ---------------------------------------------------------------------------

def recon_node(state: RTAIState) -> dict:
    agent = ReconAgent()
    return agent.run(state)


def exploit_node(state: RTAIState) -> dict:
    agent = ExploitAgent()
    return agent.run(state)


def report_node(state: RTAIState) -> dict:
    agent = ReportAgent()
    return agent.run(state)


# ---------------------------------------------------------------------------
# Routing logic
# ---------------------------------------------------------------------------

def route_after_recon(state: RTAIState) -> str:
    """Decide next node after reconnaissance completes."""
    if state.finished:
        return "report"
    # If recon found open ports / services worth investigating, go to exploit
    if state.tool_outputs.get("nmap"):
        return "exploit"
    return "report"


def route_after_exploit(state: RTAIState) -> str:
    """Decide next node after exploitation phase."""
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
        builder.add_node("exploit", exploit_node)
        builder.add_node("report", report_node)

        builder.set_entry_point("recon")

        builder.add_conditional_edges(
            "recon",
            route_after_recon,
            {"exploit": "exploit", "report": "report"},
        )
        builder.add_conditional_edges(
            "exploit",
            route_after_exploit,
            {"report": "report"},
        )
        builder.add_edge("report", END)

        return builder.compile()

    def run(self, target: str, engagement_name: str = "") -> RTAIState:
        initial = RTAIState(
            target=target,
            engagement_name=engagement_name or Config.ENGAGEMENT_NAME,
        )
        final = self._graph.invoke(initial)
        return RTAIState(**final)

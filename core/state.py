"""
core/state.py
Shared typed state object passed through every LangGraph node.
"""
from __future__ import annotations
from typing import Annotated, Any
from pydantic import BaseModel, Field
import operator


class RTAIState(BaseModel):
    # Engagement metadata
    target: str = ""
    engagement_name: str = ""

    # Findings accumulate across nodes; use list-append reducer
    findings: Annotated[list[dict[str, Any]], operator.add] = Field(default_factory=list)

    # Raw tool outputs keyed by tool name
    tool_outputs: dict[str, Any] = Field(default_factory=dict)

    # OSINT results: one entry per service queried, accumulates across nodes
    osint_results: Annotated[list[dict[str, Any]], operator.add] = Field(default_factory=list)

    # Remediation entries: one per attack vector, sorted Critical-first
    remediations: Annotated[list[dict[str, Any]], operator.add] = Field(default_factory=list)

    # Chronological log of agent actions; entries appended by each agent
    action_log: Annotated[list[dict[str, Any]], operator.add] = Field(default_factory=list)

    # Current reasoning step produced by the active agent
    current_step: str = ""

    # Set to True by any node that decides the engagement is complete
    finished: bool = False

    # Approval gate — set by SwarmController after FixerAgent generates scripts.
    # The Streamlit Dashboard shows an "Approve" button while this is True and
    # approval_granted is False; the "Apply Fixes" button is disabled until
    # approval_granted is True.
    awaiting_approval: bool = False
    approval_granted: bool = False

    # Final markdown report (populated by ReportAgent)
    report: str = ""

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

    # Current reasoning step produced by the active agent
    current_step: str = ""

    # Set to True by any node that decides the engagement is complete
    finished: bool = False

    # Final markdown report (populated by ReportAgent)
    report: str = ""

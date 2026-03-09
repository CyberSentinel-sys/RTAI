"""
agents/base_agent.py
Abstract base class for all RTAI LLM agents.

Each subclass implements `run()` which receives the shared RTAIState and
returns a partial state dict.  Callers should use the concrete `execute()`
method, which handles state merging and action logging automatically.
"""
from __future__ import annotations

import datetime
from abc import ABC, abstractmethod
from typing import Any

from langchain_openai import ChatOpenAI

from core.config import Config
from core.state import RTAIState


# ---------------------------------------------------------------------------
# Module-level utility
# ---------------------------------------------------------------------------

def _merge_partial(state: RTAIState, partial: dict[str, Any]) -> RTAIState:
    """
    Merge a partial state dict returned by an agent's ``run()`` into the
    current ``RTAIState``.

    Merging rules
    -------------
    - **list fields** – values are *appended* (mirrors LangGraph's
      ``operator.add`` reducer so behaviour is the same whether agents run
      inside or outside a LangGraph graph).
    - **dict fields** – shallow-merged (new keys win on collision).
    - **scalar fields** – overwritten by the partial value.
    - Unknown keys are silently ignored.
    """
    current = state.model_dump()
    for key, value in partial.items():
        if key not in current:
            continue
        existing = current[key]
        if isinstance(existing, list) and isinstance(value, list):
            current[key] = existing + value
        elif isinstance(existing, dict) and isinstance(value, dict):
            current[key] = {**existing, **value}
        else:
            current[key] = value
    return RTAIState(**current)


# ---------------------------------------------------------------------------
# Base agent
# ---------------------------------------------------------------------------

class BaseAgent(ABC):
    role: str = ""   # Human-readable role label shown in logs & prompts
    goal: str = ""   # One-line goal injected into every system prompt

    def __init__(self) -> None:
        self.llm = ChatOpenAI(
            model=Config.LLM_MODEL,
            temperature=Config.LLM_TEMPERATURE,
            api_key=Config.OPENAI_API_KEY,
        )

    # ------------------------------------------------------------------
    # Standard execution interface
    # ------------------------------------------------------------------

    def execute(self, state: RTAIState) -> RTAIState:
        """
        Run the agent and return an updated ``RTAIState``.

        This is the **primary public interface** for all callers (swarm
        controller, tests, etc.).  It wraps ``run()`` with:

        1. A "start" entry written to ``state.action_log``.
        2. A call to ``run()`` whose partial dict is merged into state.
        3. A "complete" entry written to ``state.action_log``.

        Parameters
        ----------
        state:
            Current shared engagement state.

        Returns
        -------
        Updated ``RTAIState`` after this agent's work is merged in.
        """
        state = _merge_partial(state, self._log_action("start"))
        partial = self.run(state)
        state = _merge_partial(state, partial)
        state = _merge_partial(state, self._log_action("complete"))
        return state

    @abstractmethod
    def run(self, state: RTAIState) -> dict[str, Any]:
        """
        Execute the agent's core task.

        Parameters
        ----------
        state:
            Current shared engagement state (read-only by convention).

        Returns
        -------
        Partial state dict whose keys are merged into ``RTAIState`` by
        ``execute()`` (or by LangGraph's reducer when used inside a graph).
        """

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _log_action(self, event: str, message: str = "", level: str = "INFO") -> dict[str, Any]:
        """
        Return a partial state dict containing a single ``action_log`` entry.

        Parameters
        ----------
        event:
            Short event label, e.g. ``"start"``, ``"complete"``,
            ``"tool_call"``.
        message:
            Optional free-text detail appended to the log entry.
        level:
            Severity label – ``"INFO"`` (default), ``"WARNING"``,
            ``"ERROR"``.
        """
        entry: dict[str, Any] = {
            "agent": self.role,
            "event": event,
            "level": level,
            "timestamp": datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        }
        if message:
            entry["message"] = message
        return {"action_log": [entry]}

    def _system_prompt(self) -> str:
        return (
            f"You are a professional red-team AI agent. Your role is: {self.role}. "
            f"Your current goal: {self.goal}. "
            "Only operate within the authorised target scope. "
            "Be concise, technical, and structured in your responses."
        )

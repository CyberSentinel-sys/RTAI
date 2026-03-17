"""
agents/base_agent.py
Abstract base class for all RTAI LLM agents.

Each subclass implements `run()` which receives the shared RTAIState and
returns a partial state dict.  Callers should use the concrete `execute()`
method, which handles state merging, action logging, and audit trail writing
automatically.

Audit Logging
-------------
Every ``execute()`` call produces two audit artefacts:

1. **In-memory action_log** (``RTAIState.action_log``) — lightweight entries
   suitable for the CISO Dashboard and Swarm Live Feed.

2. **Filesystem audit log** (``logs/<engagement>_audit.json``) — newline-
   delimited JSON records containing Agent Name, Timestamp, Action, and Tool.
   Designed for SOC 2 / HIPAA audit trail requirements.

3. **Error log** (``logs/audit_error.log``) — appended only on agent failure;
   records agent name, engagement, timestamp, exception type, and message.
"""
from __future__ import annotations

import datetime
import json
import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Union

from langchain_openai import ChatOpenAI

from core.config import Config
from core.state import RTAIState

# Resolved once at import time; agents may run with a different cwd.
_LOG_DIR = Path(__file__).resolve().parents[1] / "logs"


def _build_llm() -> Any:
    """
    Return a configured LLM instance based on ``Config``.

    Returns:
        ``ChatOllama`` when ``Config.USE_LOCAL_LLM`` is True;
        ``ChatOpenAI`` otherwise.
    """
    if Config.USE_LOCAL_LLM:
        from langchain_ollama import ChatOllama
        return ChatOllama(
            model=Config.LOCAL_LLM_MODEL,
            base_url=Config.OLLAMA_BASE_URL,
            temperature=Config.LLM_TEMPERATURE,
            format="json",
        )
    return ChatOpenAI(
        model=Config.LLM_MODEL,
        temperature=Config.LLM_TEMPERATURE,
        api_key=Config.OPENAI_API_KEY,
    )


# ---------------------------------------------------------------------------
# Module-level utility
# ---------------------------------------------------------------------------

def _merge_partial(state: RTAIState, partial: dict[str, Any]) -> RTAIState:
    """
    Merge a partial state dict returned by an agent's ``run()`` into the
    current ``RTAIState``.

    Merging rules:
        - **list fields** — values are *appended* (mirrors LangGraph's
          ``operator.add`` reducer).
        - **dict fields** — shallow-merged (new keys win on collision).
        - **scalar fields** — overwritten by the partial value.
        - Unknown keys are silently ignored.

    Args:
        state: The current shared engagement state.
        partial: Partial state dict returned by an agent's ``run()`` method.

    Returns:
        New ``RTAIState`` with the partial values merged in.
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
    """
    Abstract base class for all RTAI swarm agents.

    Subclasses implement ``run()`` and are invoked via ``execute()``, which
    handles state merging, in-memory action logging, and filesystem audit
    trail writing automatically.

    Class Attributes:
        role: Human-readable role label shown in logs and system prompts.
        goal: One-line goal injected into every LLM system prompt.
    """

    role: str = ""
    goal: str = ""

    def __init__(self) -> None:
        """Initialise the agent and build the LLM client from ``Config``."""
        self.llm: Any = _build_llm()

    # ------------------------------------------------------------------
    # Standard execution interface
    # ------------------------------------------------------------------

    def execute(self, state: RTAIState) -> RTAIState:
        """
        Run the agent and return an updated ``RTAIState``.

        This is the **primary public interface** for all callers.  It wraps
        ``run()`` with:

        1. A "start" audit entry (in-memory + filesystem).
        2. A call to ``run()`` whose partial dict is merged into state.
        3. A "complete" audit entry (in-memory + filesystem).
        4. On exception: an "error" audit entry + ``logs/audit_error.log``
           append, then the exception is re-raised.

        Args:
            state: Current shared engagement state.

        Returns:
            Updated ``RTAIState`` after this agent's work is merged in.

        Raises:
            Exception: Any exception raised by ``run()`` is re-raised after
                audit logging.
        """
        self._append_audit_log(state, event="start")
        state = _merge_partial(state, self._log_action("start"))

        try:
            partial = self.run(state)
        except Exception as exc:
            self._append_audit_log(state, event="error", tool=type(exc).__name__)
            self._write_audit_error(state, exc)
            state = _merge_partial(
                state,
                self._log_action("error", message=str(exc), level="ERROR"),
            )
            raise

        state = _merge_partial(state, partial)
        self._append_audit_log(state, event="complete")
        state = _merge_partial(state, self._log_action("complete"))
        return state

    @abstractmethod
    def run(self, state: RTAIState) -> dict[str, Any]:
        """
        Execute the agent's core task.

        Args:
            state: Current shared engagement state (read-only by convention).

        Returns:
            Partial state dict whose keys are merged into ``RTAIState`` by
            ``execute()`` (or by LangGraph's reducer when used inside a graph).
        """

    # ------------------------------------------------------------------
    # Audit logging
    # ------------------------------------------------------------------

    def _append_audit_log(
        self,
        state: RTAIState,
        event: str,
        tool: str = "",
    ) -> None:
        """
        Append a structured JSON audit record to ``logs/<engagement>_audit.json``.

        Each record contains Agent Name, Timestamp, Action Taken, Tool Used,
        and Target — the fields required for SOC 2 / HIPAA audit trails.

        Args:
            state: Current engagement state (provides engagement name + target).
            event: Action label, e.g. ``"start"``, ``"complete"``, ``"error"``.
            tool: Optional tool name invoked during this action.
        """
        try:
            _LOG_DIR.mkdir(parents=True, exist_ok=True)
            safe_name = re.sub(
                r"[^\w\-]", "_",
                getattr(state, "engagement_name", "unknown") or "unknown",
            )
            audit_path = _LOG_DIR / f"{safe_name}_audit.json"
            record: dict[str, Any] = {
                "agent":      self.role,
                "timestamp":  datetime.datetime.utcnow().isoformat(
                    timespec="seconds"
                ) + "Z",
                "action":     event,
                "tool":       tool,
                "target":     getattr(state, "target", ""),
                "engagement": getattr(state, "engagement_name", ""),
            }
            with open(audit_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        except Exception:  # noqa: BLE001
            pass  # Audit logging must never crash the pipeline

    def _write_audit_error(self, state: RTAIState, exc: Exception) -> None:
        """
        Append an error record to ``logs/audit_error.log``.

        Args:
            state: Current engagement state for context.
            exc: The exception that caused the agent failure.
        """
        try:
            _LOG_DIR.mkdir(parents=True, exist_ok=True)
            record: dict[str, Any] = {
                "agent":      self.role,
                "engagement": getattr(state, "engagement_name", "unknown"),
                "target":     getattr(state, "target", ""),
                "timestamp":  datetime.datetime.utcnow().isoformat(
                    timespec="seconds"
                ) + "Z",
                "error_type": type(exc).__name__,
                "error":      str(exc),
            }
            with open(_LOG_DIR / "audit_error.log", "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        except Exception:  # noqa: BLE001
            pass

    def _log_action(
        self,
        event: str,
        message: str = "",
        level: str = "INFO",
    ) -> dict[str, Any]:
        """
        Return a partial state dict containing a single ``action_log`` entry.

        Args:
            event: Short event label, e.g. ``"start"``, ``"complete"``,
                ``"error"``.
            message: Optional free-text detail appended to the log entry.
            level: Severity label — ``"INFO"`` (default), ``"WARNING"``,
                ``"ERROR"``.

        Returns:
            Dict with key ``"action_log"`` mapping to a single-element list.
        """
        entry: dict[str, Any] = {
            "agent":     self.role,
            "event":     event,
            "level":     level,
            "timestamp": datetime.datetime.utcnow().isoformat(
                timespec="seconds"
            ) + "Z",
        }
        if message:
            entry["message"] = message
        return {"action_log": [entry]}

    def _system_prompt(self) -> str:
        """
        Build the standard system prompt injected into every LLM call.

        Returns:
            Formatted system prompt string.
        """
        return (
            f"You are a professional red-team AI agent. Your role is: {self.role}. "
            f"Your current goal: {self.goal}. "
            "Only operate within the authorised target scope. "
            "Be concise, technical, and structured in your responses."
        )

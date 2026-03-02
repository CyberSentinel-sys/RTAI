"""
agents/base_agent.py
Abstract base class for all RTAI LLM agents.
Each subclass implements `run()` which receives the shared RTAIState,
invokes its LangChain chain / LangGraph sub-graph, and returns a
partial state dict that gets merged by the orchestrator.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from langchain_openai import ChatOpenAI

from core.config import Config
from core.state import RTAIState


class BaseAgent(ABC):
    role: str = ""          # Human-readable role label
    goal: str = ""          # One-line goal used in system prompt

    def __init__(self) -> None:
        self.llm = ChatOpenAI(
            model=Config.LLM_MODEL,
            temperature=Config.LLM_TEMPERATURE,
            api_key=Config.OPENAI_API_KEY,
        )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    @abstractmethod
    def run(self, state: RTAIState) -> dict[str, Any]:
        """
        Execute the agent's task.

        Parameters
        ----------
        state: current shared engagement state.

        Returns
        -------
        Partial state dict; keys will be merged into RTAIState by
        LangGraph's reducer logic.
        """

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _system_prompt(self) -> str:
        return (
            f"You are a professional red-team AI agent. Your role is: {self.role}. "
            f"Your current goal: {self.goal}. "
            "Only operate within the authorised target scope. "
            "Be concise, technical, and structured in your responses."
        )

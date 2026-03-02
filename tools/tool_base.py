"""
tools/tool_base.py
Abstract base class every tool wrapper must implement.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseTool(ABC):
    name: str = ""
    description: str = ""

    @abstractmethod
    def run(self, **kwargs: Any) -> dict[str, Any]:
        """Execute the tool and return a structured result dict."""

    def schema(self) -> dict[str, str]:
        return {"name": self.name, "description": self.description}

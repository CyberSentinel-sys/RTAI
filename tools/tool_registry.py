"""
tools/tool_registry.py
Central registry for all available tool wrappers.
Agents import this to discover and invoke tools by name.
"""
from __future__ import annotations

from typing import Any
from tools.tool_base import BaseTool


class ToolRegistry:
    """Singleton registry that maps tool names to ``BaseTool`` instances."""

    def __init__(self) -> None:
        self._tools: dict[str, BaseTool] = {}

    def register(self, tool: BaseTool) -> None:
        """Register *tool* under its ``name`` attribute."""
        self._tools[tool.name] = tool

    def get(self, name: str) -> BaseTool:
        """Return the tool registered under *name*, or raise ``KeyError``."""
        if name not in self._tools:
            raise KeyError(f"Tool '{name}' is not registered.")
        return self._tools[name]

    def run(self, name: str, **kwargs: Any) -> dict[str, Any]:
        """Look up *name* and call its ``run()`` method with *kwargs*."""
        return self.get(name).run(**kwargs)

    def list_tools(self) -> list[dict[str, str]]:
        """Return a list of schema dicts for every registered tool."""
        return [t.schema() for t in self._tools.values()]

    # Singleton access
    _instance: "ToolRegistry | None" = None

    @classmethod
    def default(cls) -> "ToolRegistry":
        """Return the shared singleton, creating and populating it on first call."""
        if cls._instance is None:
            from tools.nmap_wrapper import NmapTool
            cls._instance = cls()
            cls._instance.register(NmapTool())
        return cls._instance

"""
tools/tool_registry.py
Central registry for all available tool wrappers.
Agents import this to discover and invoke tools by name.
"""
from __future__ import annotations

from typing import Any
from tools.tool_base import BaseTool


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, BaseTool] = {}

    def register(self, tool: BaseTool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> BaseTool:
        if name not in self._tools:
            raise KeyError(f"Tool '{name}' is not registered.")
        return self._tools[name]

    def run(self, name: str, **kwargs: Any) -> dict[str, Any]:
        return self.get(name).run(**kwargs)

    def list_tools(self) -> list[dict[str, str]]:
        return [t.schema() for t in self._tools.values()]

    # Singleton access
    _instance: "ToolRegistry | None" = None

    @classmethod
    def default(cls) -> "ToolRegistry":
        if cls._instance is None:
            from tools.nmap_wrapper import NmapTool
            cls._instance = cls()
            cls._instance.register(NmapTool())
        return cls._instance

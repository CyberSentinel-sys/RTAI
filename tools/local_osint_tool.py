"""
tools/local_osint_tool.py
Offline OSINT tool that queries the local Exploit-DB via searchsploit.
Requires Kali Linux with the exploitdb package installed.
"""
from __future__ import annotations

import json
import subprocess
from typing import Any

from tools.tool_base import BaseTool


class LocalExploitSearchTool(BaseTool):
    name = "local_exploit_search"
    description = (
        "Search the local Exploit-DB copy via searchsploit (Kali Linux). "
        "Input: query (str). Returns top 5 exploit titles and paths as a formatted string."
    )

    def run(self, query: str = "", **kwargs: Any) -> dict[str, Any]:
        if not query:
            return {"result": "No query provided.", "exploits": []}

        try:
            proc = subprocess.run(
                ["searchsploit", "--json", query],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except FileNotFoundError:
            return {
                "result": "searchsploit is not installed or not in PATH.",
                "exploits": [],
            }
        except subprocess.TimeoutExpired:
            return {"result": "searchsploit timed out.", "exploits": []}
        except Exception as exc:  # noqa: BLE001
            return {"result": f"searchsploit error: {exc}", "exploits": []}

        if proc.returncode != 0 and not proc.stdout.strip():
            return {
                "result": f"searchsploit returned no output. stderr: {proc.stderr.strip()}",
                "exploits": [],
            }

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return {"result": "Could not parse searchsploit JSON output.", "exploits": []}

        hits = data.get("RESULTS_EXPLOIT", [])[:5]
        if not hits:
            return {"result": f"No exploits found for query: {query!r}", "exploits": []}

        exploits = [
            {
                "title": h.get("Title", "N/A"),
                "path": h.get("Path", "N/A"),
                "type": h.get("Type", "N/A"),
                "date": h.get("Date", "N/A"),
            }
            for h in hits
        ]

        lines = [f"Top {len(exploits)} local exploits for '{query}':"]
        for i, e in enumerate(exploits, 1):
            lines.append(f"  {i}. [{e['type']}] {e['title']}")
            lines.append(f"     Path: {e['path']}")

        return {"result": "\n".join(lines), "exploits": exploits}

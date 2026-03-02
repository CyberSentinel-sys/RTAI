"""
agents/report_agent.py
Report generation agent: consolidates all findings into a structured
markdown penetration-testing report.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from agents.base_agent import BaseAgent
from core.config import Config
from core.state import RTAIState


class ReportAgent(BaseAgent):
    role = "Report Writer"
    goal = "Produce a professional, structured penetration-testing report in Markdown."

    def run(self, state: RTAIState) -> dict[str, Any]:
        findings_json = json.dumps(state.findings, indent=2)

        messages = [
            SystemMessage(content=self._system_prompt()),
            HumanMessage(
                content=(
                    f"Engagement: {state.engagement_name}\n"
                    f"Target: {state.target}\n"
                    f"Date: {datetime.utcnow().strftime('%Y-%m-%d')}\n\n"
                    f"All findings (JSON):\n{findings_json}\n\n"
                    "Write a professional penetration-testing report in Markdown with "
                    "the following sections:\n"
                    "1. Executive Summary\n"
                    "2. Scope & Methodology\n"
                    "3. Findings (table: ID | Title | Risk | Description)\n"
                    "4. Detailed Findings (one sub-section per finding)\n"
                    "5. Recommendations\n"
                    "6. Conclusion\n"
                )
            ),
        ]
        response = self.llm.invoke(messages)
        report_md = response.content

        # Persist to disk
        report_path = Config.REPORT_DIR / f"{state.engagement_name}_report.md"
        report_path.write_text(report_md, encoding="utf-8")

        return {
            "report": report_md,
            "current_step": "report_complete",
            "finished": True,
        }

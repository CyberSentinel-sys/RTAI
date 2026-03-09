"""
agents/strategist_agent.py

Strategist agent: the reasoning engine of the RTAI swarm.

Reads the Analyst's ranked Exploitable Entry Points and drives a
three-step LLM reasoning chain to produce:

1. A structured **Attack Path** — a list of ``PathNode`` dicts tracing
   the attacker's progression from initial foothold through privilege
   escalation and lateral movement to the final objective.

2. A **Battle Plan** — a Markdown narrative the Fixer agent (and human
   operators) can act on immediately.

Reasoning chain
---------------
Each step receives the output of the previous step as context, forcing
the LLM to reason *incrementally* rather than hallucinating a plan that
ignores what is actually reachable.

Step 1 — Triage
    Score and rank entry points; select the top-3 footholds.
    Considers exploit reliability, CVE severity, and port reachability.
    Output: ``footholds`` JSON array.

Step 2 — Path Planning
    Given the footholds, map a realistic multi-hop attack path.
    Reasons about post-exploitation access, credential harvesting, and
    lateral movement opportunities based on discovered services.
    Output: ``path_nodes`` JSON array.

Step 3 — Battle Plan Narration
    Synthesises footholds + path into a Markdown Battle Plan with
    per-phase commands, OPSEC notes, detection indicators, and abort
    criteria.
    Output: ``battle_plan`` Markdown string.

Each step has a deterministic fallback so the chain never silently fails.

State output
------------
``tool_outputs["strategy"]``    — Battle Plan string (FixerAgent reads this)
``tool_outputs["attack_path"]`` — path_nodes list (for visualization)

``findings[phase=strategist]``  — full structured result::

    {
      "phase": "strategist",
      "target": "...",
      "battle_plan": "<markdown>",
      "attack_path": [
        {
          "step": 1,
          "type": "initial_access | privilege_escalation | lateral_movement
                   | persistence | objective",
          "ip": "...",
          "port": 22,          # integer or null
          "service": "OpenSSH 9.2p1",
          "technique": "CVE-2024-6387 ssh-agent RCE",
          "cve_id": "CVE-2024-6387",
          "severity": "Critical",
          "score": 10.0,
          "objective": "Gain shell as unprivileged user",
          "tools": ["metasploit exploit/linux/ssh/..."],
          "success_indicator": "Shell prompt on target",
          "fallback": "Try CVE-2024-6387 via manual PoC"
        },
        ...
      ],
      "path_summary": "10.0.0.1:22 → 10.0.0.1 (priv-esc) → 10.0.0.2:3306 → objective",
      "overall_risk": "Critical",
      "total_steps": 4,
      "reasoning_steps": [
        {"step": "triage",       "raw": "<LLM text>"},
        {"step": "path_planning","raw": "<LLM text>"},
        {"step": "narration",    "raw": ""}
      ]
    }
"""
from __future__ import annotations

import json
import re
import textwrap
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from agents.base_agent import BaseAgent
from core.state import RTAIState


# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------

_SEV_ORDER: dict[str, int] = {
    "critical": 0, "high": 1, "medium": 2, "low": 3,
}

# Maximum entry points sent to the LLM (avoids token overflows)
_MAX_EPS: int = 12


# ---------------------------------------------------------------------------
# Strategist agent
# ---------------------------------------------------------------------------

class StrategistAgent(BaseAgent):
    """
    Strategist agent: three-step LLM reasoning chain.

    Reads ``tool_outputs["analyst"]["entry_points"]`` (or falls back to
    findings / legacy data), then:

    1. **Triages** entry points to select the best initial footholds.
    2. **Plans** a multi-hop attack path through the network.
    3. **Narrates** a tactical Battle Plan in Markdown.

    Compatible with the ``SwarmController`` pipeline and standalone use
    via ``BaseAgent.execute()``.

    All three intermediate reasoning outputs are stored in
    ``findings[phase=strategist]["reasoning_steps"]`` for auditability.
    """

    role = "Strategist"
    goal = (
        "Reason through the Analyst's findings and design the most effective, "
        "stealthy attack path from initial foothold to final objective.  "
        "Produce a structured Attack Path and a tactical Battle Plan."
    )

    # ------------------------------------------------------------------
    # BaseAgent interface
    # ------------------------------------------------------------------

    def run(self, state: RTAIState) -> dict[str, Any]:
        target = state.target
        entry_points = self._extract_entry_points(state)

        if not entry_points:
            return self._empty_result(target)

        # ── Step 1: Triage ──────────────────────────────────────────────
        footholds, triage_raw = self._step1_triage(entry_points, target)

        # ── Step 2: Path planning ───────────────────────────────────────
        path_nodes, path_raw = self._step2_plan_path(footholds, entry_points, target)

        # ── Step 3: Battle Plan narration ───────────────────────────────
        battle_plan = self._step3_narrate(path_nodes, entry_points, target)

        # ── Metadata ────────────────────────────────────────────────────
        path_summary = self._build_path_summary(path_nodes)
        overall_risk = self._overall_risk(path_nodes)

        reasoning_steps = [
            {"step": "triage",        "raw": triage_raw},
            {"step": "path_planning", "raw": path_raw},
            {"step": "narration",     "raw": ""},   # already in battle_plan
        ]

        return self._build_partial(
            battle_plan=battle_plan,
            path_nodes=path_nodes,
            path_summary=path_summary,
            overall_risk=overall_risk,
            reasoning_steps=reasoning_steps,
            target=target,
        )

    # ------------------------------------------------------------------
    # Data extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_entry_points(state: RTAIState) -> list[dict[str, Any]]:
        """
        Extract ranked entry points from state.

        Priority
        --------
        1. ``tool_outputs["analyst"]["entry_points"]`` — AnalystAgent output
        2. ``findings[phase=analyst]["entry_points"]``  — findings fallback
        3. ``findings[phase=exploit_analysis]``          — legacy ExploitAgent
        """
        # 1. Preferred: structured AnalystAgent output
        analyst = state.tool_outputs.get("analyst", {})
        if analyst.get("entry_points"):
            return analyst["entry_points"]

        # 2. Findings fallback
        af = next(
            (f for f in state.findings
             if f.get("phase") == "analyst" and f.get("entry_points")),
            {},
        )
        if af.get("entry_points"):
            return af["entry_points"]

        # 3. Legacy ExploitAgent — text only; wrap in minimal shape
        ef = next(
            (f for f in state.findings if f.get("phase") == "exploit_analysis"),
            {},
        )
        vectors_text: str = ef.get("attack_vectors", "")
        if vectors_text:
            return [{
                "rank": 1,
                "ip": state.target,
                "port": 0,
                "protocol": "tcp",
                "service": "unknown",
                "product": "",
                "version": "",
                "severity": "High",
                "dynamic_risk_score": 7.0,
                "cves": [],
                "exploit_available": False,
                "risk_hint": vectors_text[:500],
                "analyst_notes": "",
            }]

        return []

    @staticmethod
    def _condense(entry_points: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Return a token-efficient condensed view of the top entry points."""
        return [
            {
                "rank": ep.get("rank"),
                "ip": ep.get("ip"),
                "port": ep.get("port"),
                "service": (
                    f"{ep.get('product','')} {ep.get('version','')}".strip()
                    or ep.get("service", "unknown")
                ),
                "severity": ep.get("severity"),
                "score": ep.get("dynamic_risk_score"),
                "exploit_available": ep.get("exploit_available"),
                "cves": [c.get("cve_id", "") for c in ep.get("cves", [])[:2]],
                "os": ep.get("os_context", ""),
                "analyst_notes": (ep.get("analyst_notes") or "")[:150],
            }
            for ep in entry_points[:_MAX_EPS]
        ]

    # ------------------------------------------------------------------
    # Step 1 — Triage
    # ------------------------------------------------------------------

    def _step1_triage(
        self,
        entry_points: list[dict[str, Any]],
        target: str,
    ) -> tuple[list[dict[str, Any]], str]:
        """
        Ask the LLM to select and justify the top-3 initial footholds.

        Returns ``(footholds, raw_text)``.
        Falls back to the top-3 entry points by score if JSON parsing fails.
        """
        condensed = self._condense(entry_points)

        messages = [
            SystemMessage(content=self._system_prompt()),
            HumanMessage(
                content=(
                    f"Target network: {target}\n\n"
                    "Ranked exploitable entry points (JSON):\n"
                    f"```json\n{json.dumps(condensed, indent=2)}\n```\n\n"
                    "TASK — Triage and select the TOP 3 initial footholds.\n\n"
                    "Reasoning criteria (in priority order):\n"
                    "  1. Exploit reliability: prefer exploit_available=true with known CVEs\n"
                    "  2. Severity and CVSS: Critical > High > Medium\n"
                    "  3. Service exposure: internet-facing services before internal ones\n"
                    "  4. Noise level: prefer stealthier techniques (SSH over RDP bruteforce)\n\n"
                    "Return ONLY a JSON array — no markdown fences, no preamble:\n"
                    "[\n"
                    "  {\n"
                    '    "rank": 1,\n'
                    '    "ip": "...",\n'
                    '    "port": <integer>,\n'
                    '    "service": "...",\n'
                    '    "severity": "Critical|High|Medium|Low",\n'
                    '    "score": <float>,\n'
                    '    "cve_id": "<primary CVE or N/A>",\n'
                    '    "technique": "<specific exploitation technique>",\n'
                    '    "tools": ["<tool1>", "<tool2>"],\n'
                    '    "justification": "<2-sentence reason this is the best first target>",\n'
                    '    "stealth_rating": "High|Medium|Low"\n'
                    "  }\n"
                    "]"
                )
            ),
        ]

        raw = ""
        try:
            raw = self.llm.invoke(messages).content
            parsed = self._parse_json(raw)
            if isinstance(parsed, list) and parsed:
                return parsed, raw
        except Exception:  # noqa: BLE001
            pass

        # Fallback: use top-3 by score
        return self._fallback_footholds(entry_points), raw

    # ------------------------------------------------------------------
    # Step 2 — Path planning
    # ------------------------------------------------------------------

    def _step2_plan_path(
        self,
        footholds: list[dict[str, Any]],
        entry_points: list[dict[str, Any]],
        target: str,
    ) -> tuple[list[dict[str, Any]], str]:
        """
        Given footholds and the full attack surface, plan a realistic
        multi-hop path from initial access to final objective.

        Returns ``(path_nodes, raw_text)``.
        Falls back to ``_fallback_path_nodes()`` if JSON parsing fails.
        """
        condensed = self._condense(entry_points)

        messages = [
            SystemMessage(content=self._system_prompt()),
            HumanMessage(
                content=(
                    f"Target network: {target}\n\n"
                    "── TRIAGE RESULT — Best footholds ──\n"
                    f"```json\n{json.dumps(footholds, indent=2)}\n```\n\n"
                    "── FULL ATTACK SURFACE ──\n"
                    f"```json\n{json.dumps(condensed, indent=2)}\n```\n\n"
                    "TASK — Design a realistic multi-stage attack path.\n\n"
                    "Path progression must follow realistic attacker logic:\n"
                    "  initial_access → privilege_escalation? → "
                    "lateral_movement? → persistence? → objective\n\n"
                    "For EACH step, reason about:\n"
                    "  • What access is gained (user, root, network segment)\n"
                    "  • What new services/hosts become reachable from this position\n"
                    "  • What credentials or tokens can be harvested\n"
                    "  • How to reach the next step using ONLY discovered services\n\n"
                    "Return ONLY a JSON array — no markdown fences:\n"
                    "[\n"
                    "  {\n"
                    '    "step": 1,\n'
                    '    "type": "initial_access",\n'
                    '    "ip": "...",\n'
                    '    "port": <integer or null>,\n'
                    '    "service": "...",\n'
                    '    "technique": "<ATT&CK technique name and description>",\n'
                    '    "cve_id": "<CVE or N/A>",\n'
                    '    "severity": "Critical|High|Medium|Low",\n'
                    '    "score": <float 0-10>,\n'
                    '    "objective": "<what attacker achieves at this step>",\n'
                    '    "tools": ["<specific tool or command>"],\n'
                    '    "success_indicator": "<observable sign step succeeded>",\n'
                    '    "fallback": "<alternative if this step fails>"\n'
                    "  }\n"
                    "]"
                )
            ),
        ]

        raw = ""
        try:
            raw = self.llm.invoke(messages).content
            parsed = self._parse_json(raw)
            if isinstance(parsed, list) and parsed:
                # Validate minimum required fields
                valid = [
                    n for n in parsed
                    if isinstance(n, dict) and "step" in n and "type" in n
                ]
                if valid:
                    return valid, raw
        except Exception:  # noqa: BLE001
            pass

        return self._fallback_path_nodes(footholds), raw

    # ------------------------------------------------------------------
    # Step 3 — Battle Plan narration
    # ------------------------------------------------------------------

    def _step3_narrate(
        self,
        path_nodes: list[dict[str, Any]],
        entry_points: list[dict[str, Any]],
        target: str,
    ) -> str:
        """
        Synthesise a full Markdown Battle Plan from the planned path.

        Returns the battle_plan string.
        Falls back to ``_fallback_battle_plan()`` if LLM call fails.
        """
        # Brief surface summary for context (avoid re-sending everything)
        surface_brief = (
            f"{len(entry_points)} entry point(s); "
            + ", ".join(
                f"{ep.get('ip')}:{ep.get('port')} [{ep.get('severity')}]"
                for ep in entry_points[:5]
            )
        )

        messages = [
            SystemMessage(content=self._system_prompt()),
            HumanMessage(
                content=(
                    f"Target network: {target}\n\n"
                    "── ATTACK PATH (structured) ──\n"
                    f"```json\n{json.dumps(path_nodes, indent=2)}\n```\n\n"
                    f"── ATTACK SURFACE SUMMARY ──\n{surface_brief}\n\n"
                    "TASK — Write the Battle Plan for this authorised engagement.\n\n"
                    "Format as a Markdown document with these EXACT sections:\n\n"
                    "## Battle Plan — {target}\n\n"
                    "**Overall Risk**: [highest severity across all path steps]\n"
                    "**Total Steps**: [N]\n"
                    "**Attack Path Summary**: [one-line, e.g. "
                    "10.0.0.1:22 → priv-esc → 10.0.0.2:3306 → objective]\n\n"
                    "---\n\n"
                    "### Phase N: [Step Type — e.g. Initial Access]\n"
                    "**Target**: ip:port | **Technique**: ... | **CVE**: ...\n\n"
                    "[2-3 paragraphs: specific commands, expected output, "
                    "OPSEC considerations, timing recommendations]\n\n"
                    "[repeat for each path step]\n\n"
                    "---\n\n"
                    "### Detection & IOC Notes\n"
                    "[Per-phase indicators of compromise the blue team may observe]\n\n"
                    "### Abort Criteria\n"
                    "[Conditions under which to STOP and report without further "
                    "exploitation — e.g. unexpected data encountered, "
                    "active defensive response detected]\n\n"
                    "Be specific and technical.  Use real tool names and flags.  "
                    "This plan is for an authorised engagement only."
                )
            ),
        ]

        try:
            return self.llm.invoke(messages).content
        except Exception:  # noqa: BLE001
            return self._fallback_battle_plan(path_nodes, target)

    # ------------------------------------------------------------------
    # Fallbacks
    # ------------------------------------------------------------------

    @staticmethod
    def _fallback_footholds(
        entry_points: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Use top-3 scored entry points as footholds when Step 1 fails."""
        sorted_eps = sorted(
            entry_points,
            key=lambda e: float(e.get("dynamic_risk_score", 0)),
            reverse=True,
        )
        return [
            {
                "rank": i + 1,
                "ip": ep.get("ip", "?"),
                "port": ep.get("port", 0),
                "service": (
                    f"{ep.get('product','')} {ep.get('version','')}".strip()
                    or ep.get("service", "unknown")
                ),
                "severity": ep.get("severity", "Unknown"),
                "score": ep.get("dynamic_risk_score", 0.0),
                "cve_id": next(
                    (c.get("cve_id", "N/A") for c in ep.get("cves", [])
                     if c.get("cve_id")),
                    "N/A",
                ),
                "technique": ep.get("risk_hint", "See analyst notes"),
                "tools": [],
                "justification": ep.get("analyst_notes", "Highest Dynamic Risk Score"),
                "stealth_rating": "Unknown",
            }
            for i, ep in enumerate(sorted_eps[:3])
        ]

    @staticmethod
    def _fallback_path_nodes(
        footholds: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Produce minimal path_nodes from footholds when Step 2 fails."""
        nodes: list[dict[str, Any]] = []
        step = 1
        for fh in footholds[:1]:   # Use the top foothold as initial access
            nodes.append({
                "step": step,
                "type": "initial_access",
                "ip": fh.get("ip", "?"),
                "port": fh.get("port"),
                "service": fh.get("service", "unknown"),
                "technique": fh.get("technique", "Exploit identified CVE"),
                "cve_id": fh.get("cve_id", "N/A"),
                "severity": fh.get("severity", "High"),
                "score": float(fh.get("score", 5.0)),
                "objective": "Gain initial foothold on target system",
                "tools": fh.get("tools", []),
                "success_indicator": "Shell or session established",
                "fallback": "Attempt alternative CVE or service",
            })
            step += 1

        # Add a generic objective node
        nodes.append({
            "step": step,
            "type": "objective",
            "ip": footholds[0].get("ip", "?") if footholds else "?",
            "port": None,
            "service": "host",
            "technique": "Post-exploitation enumeration",
            "cve_id": "N/A",
            "severity": "High",
            "score": 7.0,
            "objective": "Enumerate system and exfiltrate sensitive data",
            "tools": ["linpeas.sh", "find / -name '*.conf'"],
            "success_indicator": "Sensitive files or credentials retrieved",
            "fallback": "Document access level achieved and report",
        })
        return nodes

    @staticmethod
    def _fallback_battle_plan(
        path_nodes: list[dict[str, Any]],
        target: str,
    ) -> str:
        """Mechanically generate a battle plan from path_nodes when Step 3 fails."""
        lines = [
            f"## Battle Plan — {target}",
            "",
            "**Overall Risk**: See individual phase ratings below",
            f"**Total Steps**: {len(path_nodes)}",
            "**Note**: This plan was generated from structured data "
            "(LLM narration unavailable).",
            "",
            "---",
            "",
        ]
        for node in path_nodes:
            step = node.get("step", "?")
            ntype = node.get("type", "unknown").replace("_", " ").title()
            ip = node.get("ip", "?")
            port = node.get("port", "")
            svc = node.get("service", "")
            tech = node.get("technique", "")
            cve = node.get("cve_id", "N/A")
            sev = node.get("severity", "Unknown")
            obj = node.get("objective", "")
            tools = node.get("tools", [])
            indicator = node.get("success_indicator", "")
            fallback = node.get("fallback", "")

            target_str = f"{ip}:{port}" if port else ip
            lines += [
                f"### Phase {step}: {ntype}",
                f"**Target**: {target_str} | **Technique**: {tech} | "
                f"**CVE**: {cve} | **Severity**: {sev}",
                "",
                f"**Objective**: {obj}",
                "",
            ]
            if tools:
                lines.append("**Tools / Commands**:")
                for t in tools:
                    lines.append(f"- `{t}`")
                lines.append("")
            if indicator:
                lines.append(f"**Success Indicator**: {indicator}")
                lines.append("")
            if fallback:
                lines.append(f"**Fallback**: {fallback}")
                lines.append("")
            lines.append("---")
            lines.append("")

        lines += [
            "### Detection & IOC Notes",
            "Review logs for anomalous authentication attempts, "
            "unexpected outbound connections, and process executions "
            "matching tool names listed above.",
            "",
            "### Abort Criteria",
            "- Unexpected PII or sensitive data encountered beyond engagement scope",
            "- Active SOC response or defensive tooling triggered",
            "- Scope boundary breach detected",
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_json(text: str) -> Any:
        """
        Robustly extract and parse JSON from LLM output.

        Strips markdown code fences and leading prose before the first
        ``[`` or ``{``.  Returns ``None`` on any parse failure.
        """
        # Strip markdown fences
        text = re.sub(r"```(?:json)?\s*", "", text)
        text = re.sub(r"```\s*$", "", text, flags=re.MULTILINE).strip()

        # Find the outermost JSON structure
        for start_char in ("[", "{"):
            idx = text.find(start_char)
            if idx == -1:
                continue
            try:
                return json.loads(text[idx:])
            except json.JSONDecodeError:
                # Try finding the matching close bracket
                end_char = "]" if start_char == "[" else "}"
                last = text.rfind(end_char)
                if last > idx:
                    try:
                        return json.loads(text[idx : last + 1])
                    except json.JSONDecodeError:
                        pass
        return None

    @staticmethod
    def _build_path_summary(path_nodes: list[dict[str, Any]]) -> str:
        """
        Build a concise one-line path summary for display and logging.

        Example: ``"10.0.0.1:22 → 10.0.0.1 (priv-esc) → 10.0.0.2:3306 → objective"``
        """
        if not path_nodes:
            return "N/A"
        parts: list[str] = []
        for node in path_nodes:
            ip = node.get("ip", "?")
            port = node.get("port")
            ntype = node.get("type", "")
            if ntype == "objective":
                parts.append("objective")
            elif port:
                parts.append(f"{ip}:{port}")
            elif ntype:
                label = ntype.replace("_", "-")
                parts.append(f"{ip} ({label})")
            else:
                parts.append(ip)
        return " → ".join(parts)

    @staticmethod
    def _overall_risk(path_nodes: list[dict[str, Any]]) -> str:
        """Return the highest severity label across all path nodes."""
        if not path_nodes:
            return "Unknown"
        best = min(
            path_nodes,
            key=lambda n: _SEV_ORDER.get(n.get("severity", "").lower(), 99),
        )
        return best.get("severity", "Unknown")

    @staticmethod
    def _empty_result(target: str) -> dict[str, Any]:
        """Partial state dict when no entry points are available."""
        msg = (
            "No exploitable entry points available.  "
            "Run ScoutAgent and AnalystAgent before StrategistAgent."
        )
        return {
            "tool_outputs": {
                "strategy": msg,
                "attack_path": [],
            },
            "findings": [{
                "phase": "strategist",
                "target": target,
                "battle_plan": msg,
                "attack_path": [],
                "path_summary": "N/A",
                "overall_risk": "Unknown",
                "total_steps": 0,
                "reasoning_steps": [],
            }],
            "current_step": "strategist_complete",
        }

    @staticmethod
    def _build_partial(
        battle_plan: str,
        path_nodes: list[dict[str, Any]],
        path_summary: str,
        overall_risk: str,
        reasoning_steps: list[dict[str, str]],
        target: str,
    ) -> dict[str, Any]:
        return {
            "tool_outputs": {
                "strategy": battle_plan,     # string — FixerAgent reads this
                "attack_path": path_nodes,   # list[dict] — for visualization
            },
            "findings": [{
                "phase": "strategist",
                "target": target,
                "battle_plan": battle_plan,
                "attack_path": path_nodes,
                "path_summary": path_summary,
                "overall_risk": overall_risk,
                "total_steps": len(path_nodes),
                "reasoning_steps": reasoning_steps,
            }],
            "current_step": "strategist_complete",
        }

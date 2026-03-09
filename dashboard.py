"""
dashboard.py
RTAI CISO Dashboard — Swarm-powered Streamlit UI.

Tabs
----
• CISO Overview     — Risk metrics, engagement report, open ports
• Swarm Live Feed   — Real-time action_log stream; per-agent status cards
• Network Map       — streamlit-agraph host graph; high-risk nodes pulse red;
                      Strategist attack path highlighted with bold red arrows
• Remediation       — FixerAgent script viewer + DRY-RUN / apply controls

Launch:
    streamlit run dashboard.py
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import plotly.graph_objects as go
import streamlit as st
from streamlit_agraph import Config as AGraphConfig
from streamlit_agraph import Edge, Node, agraph

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

ROOT            = Path(__file__).parent
REPORTS_DIR     = ROOT / "reports"
REMEDIATION_DIR = ROOT / "remediation"
_STATE_SUFFIX   = "_state.json"

# ---------------------------------------------------------------------------
# Colour / sizing constants
# ---------------------------------------------------------------------------

RISK_LEVELS = ["Critical", "High", "Medium", "Low"]
RISK_COLORS = {
    "Critical": "#FF3B3B",
    "High":     "#FF8C00",
    "Medium":   "#FFD700",
    "Low":      "#4CAF50",
}

# agraph node sizing/border by severity
_NODE_SIZE: dict[str, int]   = {"Critical": 50, "High": 38, "Medium": 28, "Low": 22, "Unknown": 20}
_NODE_BORDER: dict[str, int] = {"Critical": 5,  "High": 3,  "Medium": 2,  "Low": 1,  "Unknown": 1}

_ATTACK_EDGE_COLOR = "#FF3B3B"
_NORMAL_EDGE_COLOR = "#3A4060"
_HOST_COLOR        = "#61AFEF"   # blue  — default host
_PORT_COLOR        = "#98C379"   # green — open port service
_ATTACKER_COLOR    = "#C678DD"   # purple

_SEV_RANK: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3}

AGENT_ICONS: dict[str, str] = {
    "Scout":      "🔭",
    "Analyst":    "🔬",
    "Strategist": "🧠",
    "Fixer":      "🔧",
}

# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

CUSTOM_CSS = """
<style>
    .stApp { background-color: #0E1117; }

    section[data-testid="stSidebar"] {
        background-color: #1A1D2E;
        border-right: 1px solid #2E3250;
    }

    div[data-testid="metric-container"] {
        background-color: #1A1D2E;
        border: 1px solid #2E3250;
        border-radius: 8px;
        padding: 16px;
    }

    .report-box {
        background-color: #1A1D2E;
        border: 1px solid #2E3250;
        border-radius: 8px;
        padding: 24px;
        font-family: monospace;
        font-size: 0.88rem;
        line-height: 1.6;
        overflow-y: auto;
        max-height: 640px;
    }

    .terminal-box {
        background-color: #0D0D0D;
        border: 1px solid #333;
        border-radius: 6px;
        padding: 16px;
        font-family: "Fira Code", "Courier New", monospace;
        font-size: 0.82rem;
        color: #98C379;
        line-height: 1.5;
        overflow-y: auto;
        max-height: 460px;
        white-space: pre-wrap;
    }

    /* Per-agent log entry rows */
    .log-entry {
        border-left: 3px solid #2E3250;
        padding: 5px 12px;
        margin: 3px 0;
        font-family: monospace;
        font-size: 0.82rem;
        border-radius: 0 4px 4px 0;
    }
    .log-start    { border-color: #61AFEF; background: #1A1D2E; }
    .log-complete { border-color: #98C379; background: #111D14; }
    .log-error    { border-color: #FF3B3B; background: #2A1010; }
    .log-warning  { border-color: #FFD700; background: #1A1810; }
    .log-info     { border-color: #2E3250; background: #1A1D2E; }

    /* Severity badges */
    .badge-critical { background:#FF3B3B; color:#fff;  padding:2px 8px; border-radius:10px; font-size:0.74rem; font-weight:700; }
    .badge-high     { background:#FF8C00; color:#fff;  padding:2px 8px; border-radius:10px; font-size:0.74rem; font-weight:700; }
    .badge-medium   { background:#FFD700; color:#111;  padding:2px 8px; border-radius:10px; font-size:0.74rem; font-weight:700; }
    .badge-low      { background:#4CAF50; color:#fff;  padding:2px 8px; border-radius:10px; font-size:0.74rem; font-weight:700; }

    /* Pulsing dot — attached to Critical/High node labels in the feed */
    @keyframes pulse-ring {
        0%   { box-shadow: 0 0 0 0 rgba(255,59,59,.7); }
        70%  { box-shadow: 0 0 0 8px rgba(255,59,59,0); }
        100% { box-shadow: 0 0 0 0 rgba(255,59,59,0);   }
    }
    .pulse-dot {
        display: inline-block;
        width: 10px; height: 10px;
        border-radius: 50%;
        background: #FF3B3B;
        margin-right: 6px;
        vertical-align: middle;
        animation: pulse-ring 1.6s ease-out infinite;
    }

    hr { border-color: #2E3250; }

    .dashboard-title {
        font-family: monospace;
        font-size: 1.6rem;
        font-weight: 700;
        color: #FF4B4B;
        letter-spacing: 0.08em;
    }
    .dashboard-sub {
        color: #7B8099;
        font-size: 0.85rem;
        font-family: monospace;
    }
</style>
"""

# ---------------------------------------------------------------------------
# Data model + report parsing (original logic preserved)
# ---------------------------------------------------------------------------

@dataclass
class EngagementReport:
    path:         Path
    engagement:   str     = ""
    target:       str     = ""
    date:         str     = ""
    risk_counts:  Counter = field(default_factory=Counter)
    ports:        list    = field(default_factory=list)
    full_text:    str     = ""

    @property
    def slug(self) -> str:
        return self.path.stem

    @property
    def total_findings(self) -> int:
        return sum(self.risk_counts.values())


def parse_report(path: Path) -> EngagementReport:
    text   = path.read_text(encoding="utf-8")
    report = EngagementReport(path=path, full_text=text)

    if m := re.search(r"\*\*Engagement\*\*\s*\|\s*([^|\n]+)", text):
        report.engagement = m.group(1).strip()
    if m := re.search(r"\*\*Target\*\*\s*\|\s*`?([^`|\n]+)`?", text):
        report.target = m.group(1).strip()
    if m := re.search(r"\*\*Date\*\*\s*\|\s*([0-9\-]+)", text):
        report.date = m.group(1).strip()

    table_risks = re.findall(
        r"\|\s*\*\*(Critical|High|Medium|Low)\*\*\s*\|", text, re.IGNORECASE,
    )
    if table_risks:
        report.risk_counts = Counter(r.capitalize() for r in table_risks)
    else:
        fallback = re.findall(
            r"\*\*[Rr]isk(?:\s+[Ll]evel)?(?:\s*:\*\*|\*\*\s*:)\s*(Critical|High|Medium|Low)",
            text, re.IGNORECASE,
        )
        report.risk_counts = Counter(r.capitalize() for r in fallback)

    report.ports = re.findall(
        r"^\|\s*(\d+)\s*\|\s*(tcp|udp)\s*\|", text, re.MULTILINE,
    )
    return report


def load_reports() -> dict[str, EngagementReport]:
    if not REPORTS_DIR.exists():
        return {}
    reports: dict[str, EngagementReport] = {}
    for md in sorted(REPORTS_DIR.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True):
        r = parse_report(md)
        reports[r.slug] = r
    return reports


# ---------------------------------------------------------------------------
# RTAIState persistence (JSON alongside report files)
# ---------------------------------------------------------------------------

def _state_path(slug: str) -> Path:
    return REPORTS_DIR / f"{slug}{_STATE_SUFFIX}"


def load_rtai_state(slug: str) -> dict[str, Any] | None:
    p = _state_path(slug)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


def save_rtai_state(slug: str, state_dict: dict[str, Any]) -> None:
    REPORTS_DIR.mkdir(exist_ok=True)
    _state_path(slug).write_text(
        json.dumps(state_dict, indent=2, default=str), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# Swarm runner — called from sidebar "Run Swarm" button
# ---------------------------------------------------------------------------

def run_swarm(target: str, engagement: str) -> dict[str, Any] | None:
    """
    Import agents lazily (avoids triggering LangChain/OpenAI init at import
    time), run every stage in SwarmController.PIPELINE sequentially, display
    per-agent status inside an st.status() block, and return the final state
    as a plain dict.  Returns None on failure.
    """
    try:
        from agents.swarm_controller import SwarmController
        from core.state import RTAIState
    except Exception as exc:
        st.error(f"Failed to load swarm agents: {exc}")
        return None

    state = RTAIState(target=target, engagement_name=engagement)

    with st.status("🚀 Running Swarm Pipeline…", expanded=True) as status:
        for AgentClass in SwarmController.PIPELINE:
            agent = AgentClass()
            icon  = AGENT_ICONS.get(agent.role, "🤖")
            st.write(f"{icon} **{agent.role}** — {agent.goal[:90]}…")
            try:
                state = agent.execute(state)
                n_entries = sum(
                    1 for e in state.action_log
                    if e.get("agent") == agent.role and e.get("event") == "complete"
                )
                st.write(f"   ✅ {agent.role} complete")
            except Exception as exc:
                st.error(f"   ✖ {agent.role} failed: {exc}")
                status.update(
                    label=f"Pipeline failed at {agent.role}", state="error"
                )
                return None

        status.update(
            label="✅ Swarm Pipeline complete!", state="complete", expanded=False
        )

    return state.model_dump()


# ---------------------------------------------------------------------------
# Plotly chart builders (unchanged from original)
# ---------------------------------------------------------------------------

def build_risk_chart(reports: dict[str, EngagementReport]) -> go.Figure:
    slugs  = list(reports.keys())
    labels = [r.engagement or r.slug for r in reports.values()]
    fig    = go.Figure()
    for level in RISK_LEVELS:
        counts = [reports[s].risk_counts.get(level, 0) for s in slugs]
        fig.add_trace(go.Bar(
            name=level, x=labels, y=counts,
            marker_color=RISK_COLORS[level],
            text=counts, textposition="outside",
            textfont=dict(color="#E0E0E0", size=12),
        ))
    fig.update_layout(
        barmode="group",
        paper_bgcolor="#0E1117", plot_bgcolor="#1A1D2E",
        font=dict(family="monospace", color="#E0E0E0"),
        legend=dict(bgcolor="#1A1D2E", bordercolor="#2E3250", borderwidth=1,
                    font=dict(size=12)),
        xaxis=dict(gridcolor="#2E3250", tickfont=dict(size=11), title=None),
        yaxis=dict(gridcolor="#2E3250", title="Finding Count", tickfont=dict(size=11)),
        margin=dict(l=40, r=20, t=20, b=40), height=360,
    )
    return fig


def build_single_donut(report: EngagementReport) -> go.Figure:
    levels = [l for l in RISK_LEVELS if report.risk_counts.get(l, 0) > 0]
    values = [report.risk_counts[l] for l in levels]
    colors = [RISK_COLORS[l] for l in levels]
    fig    = go.Figure(go.Pie(
        labels=levels, values=values, hole=0.55,
        marker=dict(colors=colors, line=dict(color="#0E1117", width=2)),
        textfont=dict(family="monospace", color="#E0E0E0", size=12),
        hovertemplate="%{label}: %{value} finding(s)<extra></extra>",
    ))
    fig.update_layout(
        paper_bgcolor="#0E1117", plot_bgcolor="#0E1117",
        font=dict(family="monospace", color="#E0E0E0"),
        legend=dict(bgcolor="#1A1D2E", bordercolor="#2E3250", borderwidth=1),
        margin=dict(l=10, r=10, t=10, b=10), height=280,
    )
    return fig


# ---------------------------------------------------------------------------
# Network map — node/edge helpers
# ---------------------------------------------------------------------------

def _nid_host(ip: str) -> str:
    return f"h_{ip.replace('.', '_')}"


def _nid_port(ip: str, port: int | str) -> str:
    return f"p_{ip.replace('.', '_')}_{port}"


def build_network_graph(
    rtai_state: dict[str, Any],
) -> tuple[list[Node], list[Edge]]:
    """
    Build streamlit-agraph Nodes and Edges from RTAIState.

    Visual encoding
    ---------------
    Host nodes    — large circles, coloured by highest analyst severity for
                    that IP.  Critical/High hosts are rendered with a thick
                    red border ring to create a "pulsing" alarm effect.
    Port nodes    — smaller circles, green by default; red if they appear in
                    the Strategist's attack path.
    Attacker node — purple star origin.
    Normal edges  — thin dark grey (topology).
    Attack-path edges — thick red arrows (width=5) between consecutive path
                        steps, giving the "bold red arrow" highlighted path.
    """
    nodes:         list[Node] = []
    edges:         list[Edge] = []
    seen_node_ids: set[str]   = set()

    scout_out   = rtai_state.get("tool_outputs", {}).get("scout",       {})
    analyst_out = rtai_state.get("tool_outputs", {}).get("analyst",     {})
    attack_path = rtai_state.get("tool_outputs", {}).get("attack_path", [])

    # ── Build per-IP max severity from analyst entry points ──────────────
    ip_severity: dict[str, str] = {}
    for ep in analyst_out.get("entry_points", []):
        ip  = ep.get("ip", "")
        sev = ep.get("severity", "Unknown").capitalize()
        cur_rank = _SEV_RANK.get(ip_severity.get(ip, "Unknown").lower(), 99)
        new_rank = _SEV_RANK.get(sev.lower(), 99)
        if new_rank < cur_rank:
            ip_severity[ip] = sev

    # ── Sets of IPs / (ip, port) pairs that appear in the attack path ────
    path_ips:   set[str]              = {s.get("ip", "") for s in attack_path}
    path_ports: set[tuple[str, Any]]  = {
        (s.get("ip", ""), s.get("port")) for s in attack_path if s.get("port")
    }

    # ── Attacker origin node ─────────────────────────────────────────────
    nodes.append(Node(
        id="attacker", label="Attacker",
        title="Attacker origin node",
        size=32, color=_ATTACKER_COLOR, shape="star",
        font={"color": "#E0E0E0", "size": 13, "face": "monospace"},
        borderWidth=2,
    ))
    seen_node_ids.add("attacker")

    def _ensure_host(ip: str) -> None:
        nid = _nid_host(ip)
        if nid in seen_node_ids:
            return
        seen_node_ids.add(nid)
        sev      = ip_severity.get(ip, "Unknown")
        in_path  = ip in path_ips
        color    = RISK_COLORS.get(sev, _HOST_COLOR)
        # Thick border ring on Critical/High hosts → visual "pulse" cue
        border_w = _NODE_BORDER.get(sev, 1) + (3 if in_path else 0)
        nodes.append(Node(
            id=nid, label=ip,
            title=f"{ip}\nSeverity: {sev}" + ("\n⚠ IN ATTACK PATH" if in_path else ""),
            size=_NODE_SIZE.get(sev, 22),
            color=color, shape="dot",
            borderWidth=border_w,
            font={"color": "#E0E0E0", "size": 13, "face": "monospace"},
        ))

    def _ensure_port(ip: str, port: int, service: str, version: str, hint: str) -> None:
        nid = _nid_port(ip, port)
        if nid in seen_node_ids:
            return
        seen_node_ids.add(nid)
        in_path = (ip, port) in path_ports
        color   = _ATTACK_EDGE_COLOR if in_path else _PORT_COLOR
        nodes.append(Node(
            id=nid, label=f":{port}",
            title=f"{ip}:{port}  {service} {version}\n{hint}",
            size=24 if in_path else 16,
            color=color, shape="dot",
            borderWidth=3 if in_path else 1,
            font={"color": "#E0E0E0", "size": 10, "face": "monospace"},
        ))

    # ── Populate from ScoutAgent structured output ────────────────────────
    scout_hosts = scout_out.get("hosts", [])
    for host in scout_hosts:
        ip = host.get("ip", "")
        if not ip:
            continue
        _ensure_host(ip)
        for op in host.get("open_ports", []):
            port    = int(op.get("port", 0))
            service = op.get("service", "")
            version = op.get("version", "")
            hint    = op.get("risk_hint", "")
            if port:
                _ensure_port(ip, port, service, version, hint)
                edges.append(Edge(
                    source=_nid_port(ip, port),
                    target=_nid_host(ip),
                    color=_NORMAL_EDGE_COLOR, width=1,
                ))

    # ── Fallback: populate from analyst entry points if scout data absent ─
    if not scout_hosts:
        for ep in analyst_out.get("entry_points", []):
            ip   = ep.get("ip", "")
            port = ep.get("port", 0)
            if ip:
                _ensure_host(ip)
            if ip and port:
                _ensure_port(ip, int(port), ep.get("service", ""),
                             ep.get("version", ""), "")
                edges.append(Edge(
                    source=_nid_port(ip, port),
                    target=_nid_host(ip),
                    color=_NORMAL_EDGE_COLOR, width=1,
                ))

    # ── Attack path — thick red arrows between consecutive steps ─────────
    if attack_path:
        # Ensure every path node exists in the graph
        for step in attack_path:
            ip   = step.get("ip", "")
            port = step.get("port")
            if ip:
                _ensure_host(ip)
            if ip and port:
                _ensure_port(ip, int(port), step.get("service", ""), "", "attack path")

        def _step_nid(step: dict[str, Any]) -> str:
            ip   = step.get("ip", "?")
            port = step.get("port")
            return _nid_port(ip, int(port)) if port else _nid_host(ip)

        # Attacker → first step
        first_nid = _step_nid(attack_path[0])
        edges.append(Edge(
            source="attacker", target=first_nid,
            color=_ATTACK_EDGE_COLOR, width=5,
            label="initial access",
        ))

        # Consecutive steps
        for i in range(len(attack_path) - 1):
            src_nid  = _step_nid(attack_path[i])
            dst_nid  = _step_nid(attack_path[i + 1])
            if src_nid == dst_nid:
                continue   # skip self-loops (priv-esc on same host)
            step_type = attack_path[i + 1].get("type", "").replace("_", "-")
            edges.append(Edge(
                source=src_nid, target=dst_nid,
                color=_ATTACK_EDGE_COLOR, width=5,
                label=step_type,
            ))

    # ── Placeholder when graph is empty ──────────────────────────────────
    if len(nodes) <= 1:
        nodes.append(Node(
            id="placeholder", label="No scan data",
            title="Run the swarm to populate this map",
            size=24, color="#2E3250", shape="diamond",
            font={"color": "#7B8099", "size": 12, "face": "monospace"},
        ))
        edges.append(Edge(
            source="attacker", target="placeholder",
            color=_NORMAL_EDGE_COLOR, width=1,
        ))

    return nodes, edges


# ---------------------------------------------------------------------------
# Shared metric card
# ---------------------------------------------------------------------------

def render_metric(label: str, value: int | str, color: str = "#E0E0E0") -> None:
    st.markdown(
        f'<div style="background:#1A1D2E;border:1px solid #2E3250;border-radius:8px;'
        f'padding:16px 20px;text-align:center;">'
        f'<div style="font-size:0.78rem;color:#7B8099;font-family:monospace;'
        f'text-transform:uppercase;letter-spacing:0.08em;">{label}</div>'
        f'<div style="font-size:2rem;font-weight:700;color:{color};'
        f'font-family:monospace;margin-top:4px;">{value}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Tab 1 — CISO Overview
# ---------------------------------------------------------------------------

def render_overview(
    selected: EngagementReport,
    reports:  dict[str, EngagementReport],
) -> None:
    cols = st.columns(5)
    for col, (label, value, color) in zip(cols, [
        ("Total Findings", selected.total_findings,                        "#E0E0E0"),
        ("Critical",       selected.risk_counts.get("Critical", 0),        RISK_COLORS["Critical"]),
        ("High",           selected.risk_counts.get("High",     0),        RISK_COLORS["High"]),
        ("Medium",         selected.risk_counts.get("Medium",   0),        RISK_COLORS["Medium"]),
        ("Low",            selected.risk_counts.get("Low",      0),        RISK_COLORS["Low"]),
    ]):
        with col:
            render_metric(label, value, color)

    st.markdown("<br>", unsafe_allow_html=True)

    chart_col, donut_col = st.columns([2, 1], gap="large")
    with chart_col:
        st.markdown("#### Risk Distribution Across All Engagements")
        st.plotly_chart(build_risk_chart(reports), use_container_width=True)
    with donut_col:
        st.markdown("#### Selected Engagement Breakdown")
        if selected.total_findings > 0:
            st.plotly_chart(build_single_donut(selected), use_container_width=True)
        else:
            st.info("No findings to display.")

    if selected.ports:
        st.divider()
        st.markdown("#### Open Ports")
        port_cols = st.columns(min(len(selected.ports), 6))
        for i, (port, proto) in enumerate(selected.ports):
            with port_cols[i % 6]:
                st.markdown(
                    f'<div style="background:#1A1D2E;border:1px solid #2E3250;'
                    f'border-radius:6px;padding:8px 12px;text-align:center;'
                    f'font-family:monospace;">'
                    f'<span style="color:#FF4B4B;font-weight:700;">{port}</span>'
                    f'<span style="color:#7B8099;font-size:0.78rem;">/{proto}</span>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
        st.markdown("<br>", unsafe_allow_html=True)

    st.divider()
    st.markdown("#### Full Report")
    with st.expander("Show / hide full report", expanded=True):
        st.markdown(
            f'<div class="report-box">{_md_to_html(selected.full_text)}</div>',
            unsafe_allow_html=True,
        )


# ---------------------------------------------------------------------------
# Tab 2 — Swarm Live Feed
# ---------------------------------------------------------------------------

def render_live_feed(rtai_state: dict[str, Any] | None) -> None:
    st.markdown("#### Swarm Execution Log")

    if not rtai_state:
        st.info(
            "No swarm run data yet.  "
            "Use **▶ Run Swarm** in the sidebar to kick off a pipeline run."
        )
        return

    action_log: list[dict[str, Any]] = rtai_state.get("action_log", [])
    target     = rtai_state.get("target", "—")
    engagement = rtai_state.get("engagement_name", "—")

    # ── Summary metrics ───────────────────────────────────────────────────
    agents_seen = list(dict.fromkeys(
        e.get("agent", "") for e in action_log if e.get("agent")
    ))
    c1, c2, c3, c4 = st.columns(4)
    with c1: render_metric("Target",      target[:22] or "—", "#61AFEF")
    with c2: render_metric("Engagement",  engagement[:20] or "—", "#98C379")
    with c3: render_metric("Agents Run",  len(agents_seen), "#E0E0E0")
    with c4: render_metric("Log Entries", len(action_log),  "#E0E0E0")
    st.markdown("<br>", unsafe_allow_html=True)

    # ── Pipeline status cards ─────────────────────────────────────────────
    if agents_seen:
        st.markdown("**Pipeline Status**")
        pcols = st.columns(len(agents_seen))
        for idx, agent_name in enumerate(agents_seen):
            completed = any(
                e.get("agent") == agent_name and e.get("event") == "complete"
                for e in action_log
            )
            errored = any(
                e.get("agent") == agent_name and e.get("level") == "ERROR"
                for e in action_log
            )
            icon        = AGENT_ICONS.get(agent_name, "🤖")
            status_icon = "✅" if completed else ("❌" if errored else "⏳")
            with pcols[idx]:
                st.markdown(
                    f'<div style="text-align:center;background:#1A1D2E;'
                    f'border:1px solid #2E3250;border-radius:8px;padding:14px;">'
                    f'<div style="font-size:1.8rem;">{icon}</div>'
                    f'<div style="font-family:monospace;font-size:0.85rem;'
                    f'color:#E0E0E0;margin-top:4px;">{agent_name}</div>'
                    f'<div style="font-size:1.4rem;margin-top:6px;">{status_icon}</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
        st.markdown("<br>", unsafe_allow_html=True)

    # ── Chronological log ─────────────────────────────────────────────────
    st.markdown("**Chronological Log**")
    if not action_log:
        st.write("No log entries recorded.")
        return

    rows: list[str] = []
    for entry in action_log:
        agent   = entry.get("agent", "System")
        event   = entry.get("event", "info")
        level   = entry.get("level", "INFO")
        ts      = entry.get("timestamp", "")
        message = entry.get("message", "")

        if event == "start":
            css_cls = "log-start"
        elif event == "complete":
            css_cls = "log-complete"
        elif level == "ERROR":
            css_cls = "log-error"
        elif level == "WARNING":
            css_cls = "log-warning"
        else:
            css_cls = "log-info"

        evt_color = {
            "log-start":    "#61AFEF",
            "log-complete": "#98C379",
            "log-error":    "#FF3B3B",
            "log-warning":  "#FFD700",
        }.get(css_cls, "#7B8099")

        icon     = AGENT_ICONS.get(agent, "🤖")
        msg_html = f' <span style="color:#7B8099;">— {message[:140]}</span>' if message else ""
        rows.append(
            f'<div class="log-entry {css_cls}">'
            f'<span style="color:#555;font-size:0.73rem;">{ts}</span> '
            f'{icon} <strong style="color:#E0E0E0;">{agent}</strong> '
            f'<span style="color:{evt_color};">[{event.upper()}]</span>'
            f'{msg_html}</div>'
        )

    st.markdown(
        '<div style="max-height:500px;overflow-y:auto;background:#1A1D2E;'
        'border:1px solid #2E3250;border-radius:8px;padding:10px;">'
        + "\n".join(rows)
        + "</div>",
        unsafe_allow_html=True,
    )

    # ── Analyst entry-points table ────────────────────────────────────────
    analyst_out = rtai_state.get("tool_outputs", {}).get("analyst", {})
    entry_points: list[dict] = analyst_out.get("entry_points", [])
    if entry_points:
        st.divider()
        st.markdown(f"**Analyst — Top Entry Points** ({len(entry_points)} total)")
        eps = sorted(
            entry_points,
            key=lambda e: float(e.get("dynamic_risk_score", 0)),
            reverse=True,
        )[:10]

        hdr = st.columns([1.5, 2.2, 0.8, 1.2, 2, 1.5])
        for h, col in zip(["IP", "Service / Product", "Port", "Severity", "Risk Score", "CVEs"], hdr):
            col.markdown(
                f'<span style="color:#7B8099;font-family:monospace;font-size:0.78rem;">{h}</span>',
                unsafe_allow_html=True,
            )
        for ep in eps:
            sev   = ep.get("severity", "Unknown")
            score = float(ep.get("dynamic_risk_score", 0))
            cves  = ", ".join(c.get("cve_id", "") for c in ep.get("cves", [])[:2]) or "—"
            badge = f'badge-{sev.lower()}'
            # Pulsing dot for Critical/High
            pulse = '<span class="pulse-dot"></span>' if sev in ("Critical", "High") else ""
            row   = st.columns([1.5, 2.2, 0.8, 1.2, 2, 1.5])
            row[0].code(ep.get("ip", ""))
            row[1].write(
                f"{ep.get('product','')} {ep.get('version','')}".strip()
                or ep.get("service", "")
            )
            row[2].write(str(ep.get("port", "")))
            row[3].markdown(
                f'{pulse}<span class="{badge}">{sev}</span>',
                unsafe_allow_html=True,
            )
            row[4].progress(min(score / 10.0, 1.0), text=f"{score:.1f}")
            row[5].write(cves)

    # ── Battle plan preview ───────────────────────────────────────────────
    strategy = rtai_state.get("tool_outputs", {}).get("strategy", "")
    if strategy:
        st.divider()
        st.markdown("**Strategist — Battle Plan Preview**")
        with st.expander("Show Battle Plan", expanded=False):
            st.markdown(strategy)


# ---------------------------------------------------------------------------
# Tab 3 — Network Map
# ---------------------------------------------------------------------------

def render_network_map(rtai_state: dict[str, Any] | None) -> None:
    st.markdown("#### Network Topology & Attack Path")

    if not rtai_state:
        st.info("No swarm data available. Run the swarm to generate the network map.")
        return

    # ── Attack path summary banner ────────────────────────────────────────
    attack_path: list[dict] = rtai_state.get("tool_outputs", {}).get("attack_path", [])
    if attack_path:
        parts: list[str] = []
        for step in attack_path:
            ip    = step.get("ip", "?")
            port  = step.get("port")
            stype = step.get("type", "").replace("_", "-")
            if stype == "objective":
                parts.append("🏁 objective")
            elif port:
                parts.append(f"<strong>{ip}:{port}</strong>")
            else:
                parts.append(f"<strong>{ip}</strong> <em>{stype}</em>")
        st.markdown(
            f'<div style="background:#2A1010;border:1px solid {_ATTACK_EDGE_COLOR};'
            f'border-radius:6px;padding:10px 14px;font-family:monospace;'
            f'font-size:0.85rem;color:#FF9090;margin-bottom:8px;">'
            f'⚔️ &nbsp;Attack Path: {" → ".join(parts)}</div>',
            unsafe_allow_html=True,
        )

    # ── Legend ────────────────────────────────────────────────────────────
    leg_cols = st.columns(6)
    for col, (label, color) in zip(leg_cols, [
        ("● Critical Host",  RISK_COLORS["Critical"]),
        ("● High Host",      RISK_COLORS["High"]),
        ("● Medium Host",    RISK_COLORS["Medium"]),
        ("● Low Host",       RISK_COLORS["Low"]),
        ("★ Attacker",       _ATTACKER_COLOR),
        ("→ Attack Path",    _ATTACK_EDGE_COLOR),
    ]):
        col.markdown(
            f'<div style="font-family:monospace;font-size:0.75rem;'
            f'color:{color};padding:2px 0;">{label}</div>',
            unsafe_allow_html=True,
        )
    st.markdown("<br>", unsafe_allow_html=True)

    # ── Build and render graph ────────────────────────────────────────────
    nodes, edges = build_network_graph(rtai_state)

    config = AGraphConfig(
        height=620,
        width=1400,
        directed=True,
        physics=True,
        hierarchical=False,
    )

    selected_node = agraph(nodes=nodes, edges=edges, config=config)
    if selected_node:
        # Show detail card for clicked node
        _render_node_detail(selected_node, rtai_state)


def _render_node_detail(node_id: str, rtai_state: dict[str, Any]) -> None:
    """Show a detail panel when a graph node is clicked."""
    analyst_out = rtai_state.get("tool_outputs", {}).get("analyst", {})
    scout_out   = rtai_state.get("tool_outputs", {}).get("scout", {})
    attack_path = rtai_state.get("tool_outputs", {}).get("attack_path", [])

    st.divider()
    st.markdown(f"**Selected node:** `{node_id}`")

    # Match to analyst entry points
    if node_id.startswith("p_"):
        # port node: p_10_0_0_1_22
        parts = node_id[2:].rsplit("_", 1)
        if len(parts) == 2:
            ip_slug, port_str = parts
            ip   = ip_slug.replace("_", ".")
            port = int(port_str) if port_str.isdigit() else 0
            eps  = [
                ep for ep in analyst_out.get("entry_points", [])
                if ep.get("ip") == ip and ep.get("port") == port
            ]
            if eps:
                ep  = eps[0]
                sev = ep.get("severity", "Unknown")
                st.markdown(
                    f'**{ip}:{port}** — {ep.get("product","")} {ep.get("version","")}'
                    f'\n\n<span class="badge-{sev.lower()}">{sev}</span> '
                    f'Score: **{ep.get("dynamic_risk_score", 0):.1f}**',
                    unsafe_allow_html=True,
                )
                cves = ep.get("cves", [])
                if cves:
                    for c in cves[:3]:
                        st.markdown(
                            f'- `{c.get("cve_id","?")}` — CVSS {c.get("cvss_v3","?")}'
                            f' {"🔴 Exploit available" if c.get("exploit_available") else ""}'
                        )
                notes = ep.get("analyst_notes", "")
                if notes:
                    st.caption(notes[:300])

    elif node_id.startswith("h_"):
        ip    = node_id[2:].replace("_", ".")
        hosts = [h for h in scout_out.get("hosts", []) if h.get("ip") == ip]
        if hosts:
            host   = hosts[0]
            osinfo = ", ".join(host.get("os_guesses", [])) or "Unknown OS"
            n_port = len(host.get("open_ports", []))
            st.markdown(f'**Host:** `{ip}` — {osinfo} — {n_port} open port(s)')
            in_path = any(s.get("ip") == ip for s in attack_path)
            if in_path:
                st.error("⚠️  This host is in the attack path.")


# ---------------------------------------------------------------------------
# Tab 4 — Remediation Center
# ---------------------------------------------------------------------------

def render_remediation_center(rtai_state: dict[str, Any] | None) -> None:
    st.markdown("#### Remediation Center")

    if not rtai_state:
        st.info("No swarm data available. Run the swarm to generate remediation scripts.")
        return

    fixer_out  = (rtai_state.get("tool_outputs") or {}).get("fixer", {})
    files      = fixer_out.get("files", {})
    fixes      = fixer_out.get("fixes", [])
    output_dir = fixer_out.get("output_dir", "")

    if not fixer_out:
        st.info("Fixer agent output not found. Ensure the full swarm pipeline has run.")
        return

    # ── Approval gate ─────────────────────────────────────────────────────
    awaiting   = rtai_state.get("awaiting_approval", False)
    approved   = rtai_state.get("approval_granted",  False)
    disruptive_count = fixer_out.get("disruptive_count", 0)

    if awaiting and not approved:
        st.warning(
            "⏳ **Approval Required** — The Fixer Agent has generated remediation "
            "scripts but they cannot be applied until you approve.  "
            "A Telegram notification has been sent to the operator.",
            icon="🔒",
        )
        if disruptive_count:
            st.error(
                f"⚠️ **{disruptive_count} Potentially Disruptive fix(es)** detected in "
                "this set. Review the Fix Inventory below before approving.",
                icon="⚠️",
            )
        if st.button("✅ Approve — I have reviewed all fixes and authorise execution",
                     type="primary", use_container_width=True):
            # Persist approval into session state and to disk
            rtai_state["approval_granted"] = True
            st.session_state["rtai_state"] = rtai_state
            slug = st.session_state.get("_loaded_slug", "")
            if slug:
                save_rtai_state(slug, rtai_state)
            st.success("Approval granted. You may now apply fixes.")
            st.rerun()
    elif awaiting and approved:
        st.success("✅ Fixes approved — Run Controls are now active.", icon="✅")

    # ── Summary metrics ───────────────────────────────────────────────────
    metric_cols = st.columns(6)
    with metric_cols[0]: render_metric("Total Fixes", fixer_out.get("total_fixes", 0),    "#E0E0E0")
    with metric_cols[1]: render_metric("Critical",    fixer_out.get("critical_count", 0), RISK_COLORS["Critical"])
    with metric_cols[2]: render_metric("High",        fixer_out.get("high_count",     0), RISK_COLORS["High"])
    with metric_cols[3]: render_metric("Medium",      fixer_out.get("medium_count",   0), RISK_COLORS["Medium"])
    with metric_cols[4]: render_metric("Low",         fixer_out.get("low_count",      0), RISK_COLORS["Low"])
    with metric_cols[5]: render_metric("Disruptive",  disruptive_count,                   "#FF8C00")
    st.markdown("<br>", unsafe_allow_html=True)

    if output_dir:
        st.caption(f"📁 Output directory: `{output_dir}`")

    # ── Fix inventory table ───────────────────────────────────────────────
    if fixes:
        st.markdown("**Fix Inventory** _(sorted Critical → Low)_")
        hdr = st.columns([1.2, 3, 1.2, 0.8, 2.2, 1.6])
        for h, col in zip(["Fix ID", "Title", "Severity", "Port", "Service", "CVE"], hdr):
            col.markdown(
                f'<span style="color:#7B8099;font-family:monospace;font-size:0.78rem;">{h}</span>',
                unsafe_allow_html=True,
            )
        for fix in fixes:
            sev        = fix.get("severity", "Unknown")
            badge      = f'badge-{sev.lower()}'
            pulse      = '<span class="pulse-dot"></span>' if sev in ("Critical", "High") else ""
            is_disrupt = fix.get("potentially_disruptive", False)
            disrupt_badge = (
                '<span style="background:#FF8C00;color:#fff;font-size:0.65rem;'
                'font-weight:700;padding:1px 5px;border-radius:3px;margin-left:4px;">'
                '⚠ DISRUPTIVE</span>'
                if is_disrupt else ""
            )
            row = st.columns([1.2, 3, 1.2, 0.8, 2.2, 1.6])
            row[0].code(fix.get("fix_id", ""))
            row[1].markdown(
                fix.get("title", "") + disrupt_badge,
                unsafe_allow_html=True,
            )
            row[2].markdown(
                f'{pulse}<span class="{badge}">{sev}</span>',
                unsafe_allow_html=True,
            )
            row[3].write(str(fix.get("port", "")))
            row[4].write(fix.get("service", "")[:32])
            row[5].write(fix.get("cve_id", "N/A"))

            # Inline disruption reasons — collapsed by default
            if is_disrupt:
                with st.expander(
                    f"⚠ {fix.get('fix_id','')} disruption details", expanded=False
                ):
                    for reason in fix.get("disruption_reasons", []):
                        st.markdown(f"- {reason}")

    st.divider()

    # ── Script file viewer (three sub-tabs) ───────────────────────────────
    bash_path    = files.get("bash",    "")
    ansible_path = files.get("ansible", "")
    index_path   = files.get("index",   "")

    script_tab, ansible_tab, index_tab = st.tabs([
        "🔧 Bash Script",
        "📋 Ansible Playbook",
        "📄 Fix Index",
    ])

    with script_tab:
        _render_script_panel(bash_path,    "Proposed_Fixes.sh",          "bash")
    with ansible_tab:
        _render_script_panel(ansible_path, "Proposed_Fixes.ansible.yml", "yaml")
    with index_tab:
        _render_script_panel(index_path,   "fix_index.txt",              "text")

    # ── Run controls ──────────────────────────────────────────────────────
    if bash_path and Path(bash_path).exists():
        st.divider()
        st.markdown("**Run Controls**")

        # Gate execution behind approval when the gate is active
        apply_locked = awaiting and not approved
        if apply_locked:
            st.info("🔒 Apply controls are locked until you approve fixes above.")

        st.warning(
            "⚠️  These commands modify system packages and firewall rules on the "
            "**local machine**.  Always run DRY RUN first.  Root / sudo required.",
            icon="⚠️",
        )
        dry_col, apply_col, _ = st.columns([2, 2, 4])
        with dry_col:
            if st.button("🔍 DRY RUN — preview changes", use_container_width=True):
                _execute_fixes(bash_path, dry_run=True)
        with apply_col:
            confirmed = st.checkbox(
                "I have reviewed the scripts and accept responsibility for applying them",
                disabled=apply_locked,
            )
            if confirmed and not apply_locked:
                if st.button(
                    "⚡ Run Proposed Fixes",
                    use_container_width=True,
                    type="primary",
                ):
                    _execute_fixes(bash_path, dry_run=False)


def _render_script_panel(file_path: str, filename: str, language: str) -> None:
    """Show file content in a code block with a download button."""
    if not file_path or not Path(file_path).exists():
        st.info(f"`{filename}` not found — run the Fixer agent to generate it.")
        return
    content = Path(file_path).read_text(encoding="utf-8")
    st.download_button(
        label=f"⬇ Download {filename}",
        data=content,
        file_name=filename,
        mime="text/plain",
        key=f"dl_{filename}",
    )
    st.code(content, language=language)


def _execute_fixes(bash_path: str, dry_run: bool) -> None:
    """Run the Bash fix script and stream output to the UI."""
    import html as _html

    mode  = "DRY RUN" if dry_run else "APPLYING FIXES"
    env   = {**os.environ, "DRY_RUN": "1" if dry_run else "0"}
    placeholder = st.empty()
    placeholder.info(f"Running {mode}…")

    try:
        result = subprocess.run(
            ["bash", bash_path, "all"],
            env=env, capture_output=True, text=True, timeout=120,
        )
        out = result.stdout
        if result.stderr:
            out += f"\n[stderr]\n{result.stderr}"
        rc = result.returncode
    except subprocess.TimeoutExpired:
        out, rc = "Script timed out after 120 seconds.", -1
    except FileNotFoundError:
        out, rc = f"bash not found or script missing: {bash_path}", -1

    placeholder.empty()
    icon = "✅" if rc == 0 else "⚠️"
    st.markdown(
        f'<div style="font-family:monospace;font-size:0.8rem;color:#7B8099;'
        f'margin-bottom:4px;">{icon} Exit code: {rc} — {mode}</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        f'<div class="terminal-box">{_html.escape(out)}</div>',
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Markdown renderer (original helper, unchanged)
# ---------------------------------------------------------------------------

def _md_to_html(md: str) -> str:
    import html
    lines  = md.split("\n")
    out:   list[str] = []
    in_code  = False
    in_table = False

    for raw in lines:
        line = raw
        if line.strip().startswith("```"):
            if not in_code:
                out.append(
                    '<pre style="background:#0E1117;border:1px solid #2E3250;'
                    'border-radius:4px;padding:10px;overflow-x:auto;color:#98C379;">'
                )
                in_code = True
            else:
                out.append("</pre>")
                in_code = False
            continue
        if in_code:
            out.append(html.escape(line) + "\n")
            continue
        if line.startswith("|"):
            if not in_table:
                out.append(
                    '<table style="width:100%;border-collapse:collapse;'
                    'font-size:0.85rem;margin:8px 0;">'
                )
                in_table = True
            if re.match(r"^\|[-| :]+\|$", line):
                continue
            cells   = [c.strip() for c in line.strip().strip("|").split("|")]
            row_html = "".join(
                f'<td style="border:1px solid #2E3250;padding:6px 10px;">'
                f'{_inline(c)}</td>' for c in cells
            )
            out.append(f"<tr>{row_html}</tr>")
            continue
        elif in_table:
            out.append("</table>")
            in_table = False
        if line.startswith("#### "):
            out.append(
                f'<h4 style="color:#FF4B4B;font-family:monospace;margin:16px 0 4px;">'
                f'{_inline(line[5:])}</h4>'
            )
        elif line.startswith("### "):
            out.append(
                f'<h3 style="color:#FF6B6B;font-family:monospace;margin:20px 0 6px;">'
                f'{_inline(line[4:])}</h3>'
            )
        elif line.startswith("## "):
            out.append(
                f'<h2 style="color:#FF4B4B;border-bottom:1px solid #2E3250;'
                f'padding-bottom:4px;margin:24px 0 8px;font-family:monospace;">'
                f'{_inline(line[3:])}</h2>'
            )
        elif line.startswith("# "):
            out.append(
                f'<h1 style="color:#FF4B4B;font-family:monospace;margin:0 0 12px;">'
                f'{_inline(line[2:])}</h1>'
            )
        elif line.startswith("- ") or line.startswith("* "):
            out.append(f'<li style="margin:2px 0;">{_inline(line[2:])}</li>')
        elif line.strip() == "---":
            out.append('<hr style="border-color:#2E3250;margin:16px 0;">')
        elif line.strip() == "":
            out.append("<br>")
        else:
            out.append(f'<p style="margin:4px 0;">{_inline(line)}</p>')

    if in_table:
        out.append("</table>")
    return "\n".join(out)


def _inline(text: str) -> str:
    import html
    t = html.escape(text)
    t = re.sub(r"\*\*(.+?)\*\*", r'<strong style="color:#E0E0E0;">\1</strong>', t)
    t = re.sub(r"\*(.+?)\*",     r"<em>\1</em>",                                 t)
    t = re.sub(
        r"`([^`]+)`",
        r'<code style="background:#0E1117;color:#98C379;padding:1px 5px;'
        r'border-radius:3px;">\1</code>',
        t,
    )
    t = re.sub(
        r"\[([^\]]+)\]\(([^)]+)\)",
        r'<a href="\2" style="color:#61AFEF;" target="_blank">\1</a>',
        t,
    )
    t = t.replace("&amp;nbsp;", "&nbsp;")
    return t


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    st.set_page_config(
        page_title="RTAI · CISO Dashboard",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

    reports = load_reports()

    # Session state initialisation
    if "rtai_state"   not in st.session_state:
        st.session_state["rtai_state"]   = None
    if "_loaded_slug" not in st.session_state:
        st.session_state["_loaded_slug"] = None

    # ── Sidebar ───────────────────────────────────────────────────────────
    with st.sidebar:
        st.markdown(
            '<div class="dashboard-title">🛡️ RTAI</div>'
            '<div class="dashboard-sub">CISO Dashboard</div>',
            unsafe_allow_html=True,
        )
        st.divider()

        selected: EngagementReport | None = None
        selected_slug = ""

        if reports:
            st.markdown("**Engagements**")
            selected_slug = st.radio(
                label="Select engagement",
                options=list(reports.keys()),
                format_func=lambda s: reports[s].engagement or s,
                label_visibility="collapsed",
            )
            st.divider()
            selected = reports[selected_slug]
            st.markdown("**Engagement details**")
            st.markdown(f"🎯 **Target:** `{selected.target}`")
            st.markdown(f"📅 **Date:**   {selected.date}")
            st.markdown(f"📄 **File:**   `{selected.path.name}`")
            st.divider()

            # Auto-load saved state when a different report is selected
            if st.session_state["_loaded_slug"] != selected_slug:
                saved = load_rtai_state(selected_slug)
                if saved:
                    st.session_state["rtai_state"]   = saved
                    st.session_state["_loaded_slug"] = selected_slug
        else:
            st.warning("No reports in `reports/`. Run a swarm engagement first.")

        # ── Swarm Control Panel ───────────────────────────────────────────
        st.markdown("**🚀 Run New Swarm**")
        swarm_target     = st.text_input("Target IP / Range",  placeholder="192.168.1.0/24")
        swarm_engagement = st.text_input("Engagement Name",    placeholder="MyEngagement_2026")

        if st.button("▶ Run Swarm", use_container_width=True, type="primary"):
            if not swarm_target.strip():
                st.error("Target is required.")
            elif not swarm_engagement.strip():
                st.error("Engagement name is required.")
            else:
                state_dict = run_swarm(swarm_target.strip(), swarm_engagement.strip())
                if state_dict:
                    st.session_state["rtai_state"] = state_dict
                    # Persist alongside reports so it reloads next session
                    safe_slug = "".join(
                        c if c.isalnum() or c in "-_" else "_"
                        for c in swarm_engagement.strip()
                    )
                    save_rtai_state(safe_slug, state_dict)
                    st.session_state["_loaded_slug"] = safe_slug
                    st.success("Swarm complete! See Swarm Live Feed tab.")
                    st.rerun()

        st.divider()
        st.markdown(
            '<div class="dashboard-sub">RTAI swarm pipeline<br>'
            'Scout → Analyst → Strategist → Fixer</div>',
            unsafe_allow_html=True,
        )

    # ── Page header ───────────────────────────────────────────────────────
    title      = (selected.engagement if selected else swarm_engagement) or "RTAI Dashboard"
    target_str = (selected.target     if selected else swarm_target)     or "—"
    date_str   = (selected.date       if selected else "")               or ""
    st.markdown(
        f'<div class="dashboard-title">🛡️ {title}</div>'
        f'<div class="dashboard-sub">Target: {target_str}'
        + (f' &nbsp;·&nbsp; {date_str}' if date_str else "")
        + "</div>",
        unsafe_allow_html=True,
    )
    st.divider()

    # ── Tabs ──────────────────────────────────────────────────────────────
    rtai_state = st.session_state.get("rtai_state")

    if selected:
        t_overview, t_feed, t_map, t_remediation = st.tabs([
            "📊 CISO Overview",
            "📡 Swarm Live Feed",
            "🗺️ Network Map",
            "🔧 Remediation Center",
        ])
        with t_overview:
            render_overview(selected, reports)
    else:
        t_feed, t_map, t_remediation = st.tabs([
            "📡 Swarm Live Feed",
            "🗺️ Network Map",
            "🔧 Remediation Center",
        ])

    with t_feed:
        render_live_feed(rtai_state)
    with t_map:
        render_network_map(rtai_state)
    with t_remediation:
        render_remediation_center(rtai_state)


if __name__ == "__main__":
    main()

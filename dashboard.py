"""
dashboard.py
RTAI CISO Dashboard — Streamlit UI for visualising engagement reports.

Launch:
    streamlit run dashboard.py
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import plotly.graph_objects as go
import streamlit as st

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REPORTS_DIR = Path(__file__).parent / "reports"

RISK_LEVELS   = ["Critical", "High", "Medium", "Low"]
RISK_COLORS   = {
    "Critical": "#FF3B3B",
    "High":     "#FF8C00",
    "Medium":   "#FFD700",
    "Low":      "#4CAF50",
}

# CSS injected for fine-grained dark styling
CUSTOM_CSS = """
<style>
    /* Main background */
    .stApp { background-color: #0E1117; }

    /* Sidebar */
    section[data-testid="stSidebar"] {
        background-color: #1A1D2E;
        border-right: 1px solid #2E3250;
    }

    /* Metric cards */
    div[data-testid="metric-container"] {
        background-color: #1A1D2E;
        border: 1px solid #2E3250;
        border-radius: 8px;
        padding: 16px;
    }

    /* Report markdown area */
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

    /* Section dividers */
    hr { border-color: #2E3250; }

    /* Header accent */
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
# Data model
# ---------------------------------------------------------------------------

@dataclass
class EngagementReport:
    path:         Path
    engagement:   str = ""
    target:       str = ""
    date:         str = ""
    risk_counts:  Counter = field(default_factory=Counter)
    ports:        list[str] = field(default_factory=list)
    full_text:    str = ""

    @property
    def slug(self) -> str:
        return self.path.stem

    @property
    def total_findings(self) -> int:
        return sum(self.risk_counts.values())


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_report(path: Path) -> EngagementReport:
    text = path.read_text(encoding="utf-8")
    report = EngagementReport(path=path, full_text=text)

    # ── Metadata from header table ────────────────────────────────────────
    if m := re.search(r"\*\*Engagement\*\*\s*\|\s*([^|\n]+)", text):
        report.engagement = m.group(1).strip()
    if m := re.search(r"\*\*Target\*\*\s*\|\s*`?([^`|\n]+)`?", text):
        report.target = m.group(1).strip()
    if m := re.search(r"\*\*Date\*\*\s*\|\s*([0-9\-]+)", text):
        report.date = m.group(1).strip()

    # ── Risk levels — primary source: Remediation Plan table ─────────────
    # Matches rows like:  | 1 | Title | **High** | Service | CVE |
    table_risks = re.findall(
        r"\|\s*\*\*(Critical|High|Medium|Low)\*\*\s*\|",
        text, re.IGNORECASE,
    )

    if table_risks:
        report.risk_counts = Counter(r.capitalize() for r in table_risks)
    else:
        # Fallback: parse "**Risk:** High" or "Risk Level: High" lines
        fallback = re.findall(
            r"\*\*[Rr]isk(?:\s+[Ll]evel)?(?:\s*:\*\*|\*\*\s*:)\s*(Critical|High|Medium|Low)",
            text, re.IGNORECASE,
        )
        report.risk_counts = Counter(r.capitalize() for r in fallback)

    # ── Open ports from Recon table ───────────────────────────────────────
    # Matches rows like:  | 80 | tcp | http | ...
    report.ports = re.findall(
        r"^\|\s*(\d+)\s*\|\s*(tcp|udp)\s*\|",
        text, re.MULTILINE,
    )

    return report


def load_reports() -> dict[str, EngagementReport]:
    if not REPORTS_DIR.exists():
        return {}
    reports = {}
    for md in sorted(REPORTS_DIR.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True):
        r = parse_report(md)
        reports[r.slug] = r
    return reports


# ---------------------------------------------------------------------------
# Chart
# ---------------------------------------------------------------------------

def build_risk_chart(reports: dict[str, EngagementReport]) -> go.Figure:
    """Grouped bar chart: one bar per risk level, one group per engagement."""
    slugs = list(reports.keys())
    labels = [r.engagement or r.slug for r in reports.values()]

    fig = go.Figure()
    for level in RISK_LEVELS:
        counts = [reports[s].risk_counts.get(level, 0) for s in slugs]
        fig.add_trace(go.Bar(
            name=level,
            x=labels,
            y=counts,
            marker_color=RISK_COLORS[level],
            text=counts,
            textposition="outside",
            textfont=dict(color="#E0E0E0", size=12),
        ))

    fig.update_layout(
        barmode="group",
        paper_bgcolor="#0E1117",
        plot_bgcolor="#1A1D2E",
        font=dict(family="monospace", color="#E0E0E0"),
        legend=dict(
            bgcolor="#1A1D2E",
            bordercolor="#2E3250",
            borderwidth=1,
            font=dict(size=12),
        ),
        xaxis=dict(
            gridcolor="#2E3250",
            tickfont=dict(size=11),
            title=None,
        ),
        yaxis=dict(
            gridcolor="#2E3250",
            title="Finding Count",
            tickfont=dict(size=11),
        ),
        margin=dict(l=40, r=20, t=20, b=40),
        height=360,
    )
    return fig


def build_single_donut(report: EngagementReport) -> go.Figure:
    """Donut chart for a single engagement's risk breakdown."""
    levels  = [l for l in RISK_LEVELS if report.risk_counts.get(l, 0) > 0]
    values  = [report.risk_counts[l] for l in levels]
    colors  = [RISK_COLORS[l] for l in levels]

    fig = go.Figure(go.Pie(
        labels=levels,
        values=values,
        hole=0.55,
        marker=dict(colors=colors, line=dict(color="#0E1117", width=2)),
        textfont=dict(family="monospace", color="#E0E0E0", size=12),
        hovertemplate="%{label}: %{value} finding(s)<extra></extra>",
    ))
    fig.update_layout(
        paper_bgcolor="#0E1117",
        plot_bgcolor="#0E1117",
        font=dict(family="monospace", color="#E0E0E0"),
        legend=dict(bgcolor="#1A1D2E", bordercolor="#2E3250", borderwidth=1),
        margin=dict(l=10, r=10, t=10, b=10),
        height=280,
        showlegend=True,
    )
    return fig


# ---------------------------------------------------------------------------
# Page layout
# ---------------------------------------------------------------------------

def render_metric(label: str, value: int | str, color: str = "#E0E0E0") -> None:
    st.markdown(
        f"""
        <div style="background:#1A1D2E;border:1px solid #2E3250;border-radius:8px;
                    padding:16px 20px;text-align:center;">
            <div style="font-size:0.78rem;color:#7B8099;font-family:monospace;
                        text-transform:uppercase;letter-spacing:0.08em;">{label}</div>
            <div style="font-size:2rem;font-weight:700;color:{color};
                        font-family:monospace;margin-top:4px;">{value}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def main() -> None:
    st.set_page_config(
        page_title="RTAI · CISO Dashboard",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

    reports = load_reports()

    # ── Sidebar ───────────────────────────────────────────────────────────
    with st.sidebar:
        st.markdown(
            '<div class="dashboard-title">🛡️ RTAI</div>'
            '<div class="dashboard-sub">CISO Dashboard</div>',
            unsafe_allow_html=True,
        )
        st.divider()

        if not reports:
            st.warning("No reports found in `reports/`.")
            st.stop()

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
        st.markdown(f"📅 **Date:** {selected.date}")
        st.markdown(f"📄 **File:** `{selected.path.name}`")
        st.divider()
        st.markdown(
            '<div class="dashboard-sub">Generated by RTAI pipeline<br>'
            'recon → osint → exploit → remediation → report</div>',
            unsafe_allow_html=True,
        )

    # ── Header ────────────────────────────────────────────────────────────
    st.markdown(
        f'<div class="dashboard-title">🛡️ {selected.engagement or selected_slug}</div>'
        f'<div class="dashboard-sub">Target: {selected.target} &nbsp;·&nbsp; {selected.date}</div>',
        unsafe_allow_html=True,
    )
    st.divider()

    # ── Metric cards ──────────────────────────────────────────────────────
    cols = st.columns(5)
    metrics = [
        ("Total Findings",  selected.total_findings,                        "#E0E0E0"),
        ("Critical",        selected.risk_counts.get("Critical", 0),        RISK_COLORS["Critical"]),
        ("High",            selected.risk_counts.get("High",     0),        RISK_COLORS["High"]),
        ("Medium",          selected.risk_counts.get("Medium",   0),        RISK_COLORS["Medium"]),
        ("Low",             selected.risk_counts.get("Low",      0),        RISK_COLORS["Low"]),
    ]
    for col, (label, value, color) in zip(cols, metrics):
        with col:
            render_metric(label, value, color)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Charts ────────────────────────────────────────────────────────────
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

    st.divider()

    # ── Open ports table ──────────────────────────────────────────────────
    if selected.ports:
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

    # ── Full report ───────────────────────────────────────────────────────
    st.markdown("#### Full Report")
    with st.expander("Show / hide full report", expanded=True):
        st.markdown(
            f'<div class="report-box">{_md_to_html(selected.full_text)}</div>',
            unsafe_allow_html=True,
        )


def _md_to_html(md: str) -> str:
    """Minimal Markdown → HTML for the report box (headings, bold, code, tables)."""
    import html
    lines = md.split("\n")
    out: list[str] = []
    in_code = False
    in_table = False

    for raw in lines:
        line = raw

        # Code fences
        if line.strip().startswith("```"):
            if not in_code:
                lang = line.strip().lstrip("`").strip() or "bash"
                out.append(f'<pre style="background:#0E1117;border:1px solid #2E3250;'
                           f'border-radius:4px;padding:10px;overflow-x:auto;'
                           f'color:#98C379;">')
                in_code = True
            else:
                out.append("</pre>")
                in_code = False
            continue

        if in_code:
            out.append(html.escape(line) + "\n")
            continue

        # Tables
        if line.startswith("|"):
            if not in_table:
                out.append('<table style="width:100%;border-collapse:collapse;'
                           'font-size:0.85rem;margin:8px 0;">')
                in_table = True
            if re.match(r"^\|[-| :]+\|$", line):
                continue  # separator row
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            row_html = "".join(
                f'<td style="border:1px solid #2E3250;padding:6px 10px;">'
                f'{_inline(c)}</td>' for c in cells
            )
            out.append(f"<tr>{row_html}</tr>")
            continue
        elif in_table:
            out.append("</table>")
            in_table = False

        # Headings
        if line.startswith("#### "):
            out.append(f'<h4 style="color:#FF4B4B;font-family:monospace;'
                       f'margin:16px 0 4px;">{_inline(line[5:])}</h4>')
        elif line.startswith("### "):
            out.append(f'<h3 style="color:#FF6B6B;font-family:monospace;'
                       f'margin:20px 0 6px;">{_inline(line[4:])}</h3>')
        elif line.startswith("## "):
            out.append(f'<h2 style="color:#FF4B4B;border-bottom:1px solid #2E3250;'
                       f'padding-bottom:4px;margin:24px 0 8px;font-family:monospace;">'
                       f'{_inline(line[3:])}</h2>')
        elif line.startswith("# "):
            out.append(f'<h1 style="color:#FF4B4B;font-family:monospace;'
                       f'margin:0 0 12px;">{_inline(line[2:])}</h1>')
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
    """Process inline markdown: bold, italic, inline code, links."""
    import html
    t = html.escape(text)
    # Bold
    t = re.sub(r"\*\*(.+?)\*\*",
               r'<strong style="color:#E0E0E0;">\1</strong>', t)
    # Italic
    t = re.sub(r"\*(.+?)\*", r"<em>\1</em>", t)
    # Inline code / backtick
    t = re.sub(r"`([^`]+)`",
               r'<code style="background:#0E1117;color:#98C379;'
               r'padding:1px 5px;border-radius:3px;">\1</code>', t)
    # Markdown links [text](url)
    t = re.sub(r"\[([^\]]+)\]\(([^)]+)\)",
               r'<a href="\2" style="color:#61AFEF;" target="_blank">\1</a>', t)
    # &nbsp; passthrough
    t = t.replace("&amp;nbsp;", "&nbsp;")
    return t


if __name__ == "__main__":
    main()

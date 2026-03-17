"""
tools/telegram_notifier.py

Sends ONE single Telegram message per swarm run containing all results:
  - Engagement header + overall risk
  - Scout: every host with all open ports, services, versions, risk hints
  - Analyst: CVE entry points with severity + Dynamic Risk Scores
  - Strategist: attack path steps + battle plan summary
  - Fixer: proposed remediations list

Telegram hard limit is 4096 chars. Content is trimmed to fit while keeping
all sections visible. If TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID are missing
the send is silently skipped.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

_LIMIT = 4096


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def notify_telegram(
    engagement: str,
    target: str,
    report_md: str = "",
    state: dict[str, Any] | None = None,
) -> bool:
    """Build one message and send it. Returns True on success."""
    from core.config import Config

    token   = Config.TELEGRAM_BOT_TOKEN.strip()
    chat_id = Config.TELEGRAM_CHAT_ID.strip()

    if not token or not chat_id or chat_id == "your_id_here":
        return False

    msg = _build(engagement, target, state or {})
    return _send(token, chat_id, msg)


# ---------------------------------------------------------------------------
# Single-message builder
# ---------------------------------------------------------------------------

def _build(engagement: str, target: str, state: dict[str, Any]) -> str:
    scout       = state.get("tool_outputs", {}).get("scout",   {})
    analyst     = state.get("tool_outputs", {}).get("analyst", {})
    attack_path = state.get("tool_outputs", {}).get("attack_path", [])
    findings    = state.get("findings", [])

    strat_f = next((f for f in findings if f.get("phase") == "strategist"), {})
    fixer_f = next((f for f in findings if f.get("phase") == "fixer"),      {})

    meta    = scout.get("scan_metadata", {})
    surface = scout.get("attack_surface", {})

    risk       = strat_f.get("overall_risk", "Unknown")
    risk_emoji = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🟢","Minimal":"🟢"}.get(risk,"⚪")
    timestamp  = meta.get("timestamp", "")
    hosts_up   = surface.get("total_hosts_up", 0)
    open_ports = surface.get("total_open_ports", 0)
    high_risk  = surface.get("high_risk_ports", [])
    scan_mode  = meta.get("scan_mode", "unknown")

    lines: list[str] = []

    # ── Header ───────────────────────────────────────────────────────────
    lines += [
        f"🛡 *RTAI — {engagement}*",
        f"🎯 Target: `{target}`   🕐 {timestamp}",
        f"{risk_emoji} Overall Risk: *{risk}*",
        f"🖥 Hosts: {hosts_up}   🔓 Open ports: {open_ports}   "
        f"⚠ High-risk: {', '.join(str(p) for p in high_risk) or 'none'}",
        f"🔍 Scan mode: {scan_mode}",
        "━" * 30,
    ]

    # ── Scout: hosts + ports ─────────────────────────────────────────────
    hosts = scout.get("hosts", [])
    if hosts:
        lines.append("*SCOUT — HOSTS & PORTS*")
        for host in hosts:
            ip      = host.get("ip", "?")
            os_list = host.get("os_guesses", [])
            os_str  = f" ({os_list[0]['name'][:30]})" if os_list else ""
            lines.append(f"🔵 *{ip}*{os_str}")
            ports = host.get("open_ports", [])
            if ports:
                for p in ports:
                    port    = p.get("port", "?")
                    proto   = p.get("protocol", "tcp")
                    svc     = p.get("service", "")
                    product = p.get("product", "")
                    ver     = p.get("version", "")
                    hint    = p.get("risk_hint", "")
                    svc_str = " ".join(filter(None, [svc, product, ver]))[:40]
                    hint_str = f" — {hint[:60]}" if hint else ""
                    lines.append(f"  `{port}/{proto}` {svc_str}{hint_str}")
            else:
                lines.append("  no open ports")
        lines.append("━" * 30)

    # ── Analyst: CVE entry points ─────────────────────────────────────────
    entry_points = analyst.get("entry_points", [])
    if entry_points:
        lines.append("*ANALYST — CVE ENTRY POINTS*")
        for ep in entry_points:
            sev  = ep.get("severity", "?")
            se   = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🟢"}.get(sev.lower(),"⚪")
            ip   = ep.get("ip", "?")
            port = ep.get("port", "?")
            svc  = ep.get("service", "")
            ver  = ep.get("version", "")
            drs  = ep.get("dynamic_risk_score", "?")
            cves = ep.get("cves", [])
            svc_str = f"{svc} {ver}".strip()[:30]
            cve_str = f" CVEs: {', '.join(cves[:3])}" if cves else ""
            lines.append(f"{se} `{ip}:{port}` {svc_str} | Score:{drs}{cve_str}")
        lines.append("━" * 30)

    # ── Strategist: attack path + plan ───────────────────────────────────
    plan = strat_f.get("battle_plan", "")
    if attack_path or plan:
        lines.append("*STRATEGIST — ATTACK PATH*")
        if attack_path:
            for i, step in enumerate(attack_path, 1):
                ip    = step.get("ip", "?")
                port  = step.get("port", "")
                stype = step.get("type", "").replace("_", "-")[:20]
                svc   = step.get("service", "")[:15]
                t     = f"{ip}:{port}" if port else ip
                lines.append(f"  {i}. `{t}` {stype} {svc}".rstrip())
        if plan and plan != "No exploitable entry points available.  Run ScoutAgent and AnalystAgent before StrategistAgent.":
            lines.append(f"Plan: {plan[:300]}")
        lines.append("━" * 30)

    # ── Fixer: remediations ───────────────────────────────────────────────
    fixer_out = state.get("tool_outputs", {}).get("fixer", {})
    fixes     = fixer_out.get("fixes", [])
    total     = fixer_f.get("total_fixes", 0)
    out_dir   = fixer_f.get("output_dir", "")
    if total or fixes:
        lines.append(f"*FIXER — {total} REMEDIATIONS*")
        if out_dir:
            lines.append(f"Scripts: `{out_dir}`")
        for fix in fixes[:8]:
            sev  = fix.get("severity", "")
            se   = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🟢"}.get(sev.lower(),"⚪")
            ip   = fix.get("ip", "?")
            port = fix.get("port", "?")
            svc  = fix.get("service", "")[:20]
            desc = fix.get("description", "")[:80]
            lines.append(f"{se} `{ip}:{port}` {svc} — {desc}")
        if len(fixes) > 8:
            lines.append(f"  +{len(fixes)-8} more in saved scripts")

    # ── Assemble and trim to fit ──────────────────────────────────────────
    msg = "\n".join(lines)
    if len(msg) > _LIMIT:
        msg = msg[:_LIMIT - 20] + "\n…(truncated)"
    return msg


# ---------------------------------------------------------------------------
# Send
# ---------------------------------------------------------------------------

def _send(token: str, chat_id: str, text: str) -> bool:
    """POST to Telegram; falls back to plain text if Markdown parse fails."""
    url = f"https://api.telegram.org/bot{token}/sendMessage"

    def _post(payload: dict) -> bool:
        data = json.dumps(payload).encode()
        req  = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status == 200
        except urllib.error.HTTPError:
            return False
        except Exception:
            return False

    if _post({"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}):
        return True
    # Markdown failed (unmatched symbols) — retry as plain text
    return _post({"chat_id": chat_id, "text": text})

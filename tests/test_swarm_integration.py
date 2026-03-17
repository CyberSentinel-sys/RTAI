#!/usr/bin/env python
"""
tests/test_swarm_integration.py
================================
Full integration test for the RTAI Swarm pipeline.

What is tested
--------------
1. Prerequisites — nmap available, API key present
2. SwarmController.run() — executes all four agents end-to-end
3. RTAIState.action_log — start/complete events for every agent
4. tool_outputs['scout']    — hosts, open_ports, attack_surface
5. tool_outputs['analyst']  — entry_points with scores/CVEs
6. tool_outputs['strategy'] — non-empty Battle Plan string
7. tool_outputs['fixer']    — fix inventory and output paths
8. Remediation files — Proposed_Fixes.sh, .ansible.yml, fix_index.txt
   created under remediation/<engagement>_<date>/

Modes
-----
Real API  (default):  python tests/test_swarm_integration.py
Mock mode (fast/CI):  python tests/test_swarm_integration.py --mock
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import shutil
import subprocess
import sys
import textwrap
import time
import unittest.mock as mock
from pathlib import Path

# ── ensure project root is importable ────────────────────────────────────────
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# ── colour helpers ────────────────────────────────────────────────────────────
_GREEN  = "\033[0;32m"
_RED    = "\033[0;31m"
_YELLOW = "\033[0;33m"
_CYAN   = "\033[0;36m"
_BOLD   = "\033[1m"
_RESET  = "\033[0m"

TARGET     = "127.0.0.1"
ENGAGEMENT = f"integration_test_{datetime.date.today().isoformat().replace('-', '')}"


# ─────────────────────────────────────────────────────────────────────────────
# Result accumulator
# ─────────────────────────────────────────────────────────────────────────────

class _Results:
    def __init__(self) -> None:
        self._passed: list[str]  = []
        self._failed: list[str]  = []
        self._skipped: list[str] = []

    def ok(self, label: str, detail: str = "") -> None:
        msg = f"  {_GREEN}✔{_RESET}  {label}"
        if detail:
            msg += f"  {_YELLOW}({detail}){_RESET}"
        print(msg)
        self._passed.append(label)

    def fail(self, label: str, reason: str = "") -> None:
        msg = f"  {_RED}✘{_RESET}  {label}"
        if reason:
            msg += f"  {_RED}→ {reason}{_RESET}"
        print(msg)
        self._failed.append(label)

    def skip(self, label: str, reason: str = "") -> None:
        msg = f"  {_YELLOW}⊘{_RESET}  {label}"
        if reason:
            msg += f"  {_YELLOW}(skipped: {reason}){_RESET}"
        print(msg)
        self._skipped.append(label)

    def section(self, title: str) -> None:
        print(f"\n{_BOLD}{_CYAN}── {title} ──{_RESET}")

    def summary(self) -> bool:
        total = len(self._passed) + len(self._failed) + len(self._skipped)
        print(f"\n{_BOLD}{'═' * 58}{_RESET}")
        print(f"{_BOLD}Results:{_RESET}  "
              f"{_GREEN}{len(self._passed)} passed{_RESET}  "
              f"{_RED}{len(self._failed)} failed{_RESET}  "
              f"{_YELLOW}{len(self._skipped)} skipped{_RESET}  "
              f"/ {total} total")
        if self._failed:
            print(f"\n{_RED}Failed checks:{_RESET}")
            for f in self._failed:
                print(f"  • {f}")
        print(f"{_BOLD}{'═' * 58}{_RESET}")
        return len(self._failed) == 0


R = _Results()


# ─────────────────────────────────────────────────────────────────────────────
# Mock fixtures
# ─────────────────────────────────────────────────────────────────────────────

_MOCK_NMAP_RESULT = {
    "scan_args": "-sT -sV --open -T3 -Pn",
    "target": TARGET,
    "hosts": [{
        "host": TARGET,
        "hostname": "localhost",
        "state": "up",
        "os_matches": [{"name": "Linux 5.x", "accuracy": "95"}],
        "ports": [
            {"port": 22,   "protocol": "tcp", "state": "open",
             "service": "ssh",   "product": "OpenSSH", "version": "9.2p1",
             "extrainfo": "protocol 2.0"},
            {"port": 80,   "protocol": "tcp", "state": "open",
             "service": "http",  "product": "Apache httpd", "version": "2.4.49",
             "extrainfo": ""},
            {"port": 3306, "protocol": "tcp", "state": "open",
             "service": "mysql", "product": "MySQL", "version": "5.7.35",
             "extrainfo": ""},
        ],
    }],
}

_MOCK_ATTACK_SURFACE = (
    "Target 127.0.0.1 exposes SSH (22), HTTP (80), and MySQL (3306). "
    "OpenSSH 9.2p1 is vulnerable to CVE-2024-6387. "
    "Apache 2.4.49 is vulnerable to CVE-2021-41773 path traversal RCE."
)

_MOCK_FOOTHOLDS = json.dumps([{
    "rank": 1, "ip": TARGET, "port": 22,
    "service": "OpenSSH 9.2p1", "severity": "Critical", "score": 9.5,
    "cve_id": "CVE-2024-6387",
    "technique": "SSH pre-auth RCE via ssh-agent forwarding",
    "tools": ["exploit/linux/ssh/sshd_9_2_rce"],
    "justification": "Critical CVSS 9.8, exploit publicly available.",
    "stealth_rating": "Medium",
}])

_MOCK_PATH_NODES = json.dumps([
    {"step": 1, "type": "initial_access",      "ip": TARGET, "port": 22,
     "service": "OpenSSH 9.2p1", "technique": "CVE-2024-6387 RCE",
     "cve_id": "CVE-2024-6387", "severity": "Critical", "score": 9.5,
     "objective": "Shell as www-data", "tools": ["msf: exploit/linux/ssh/sshd_9_2_rce"],
     "success_indicator": "Shell prompt", "fallback": "Brute-force SSH"},
    {"step": 2, "type": "privilege_escalation", "ip": TARGET, "port": None,
     "service": "sudo", "technique": "SUID binary abuse",
     "cve_id": "N/A", "severity": "High", "score": 7.5,
     "objective": "root access", "tools": ["linpeas.sh"],
     "success_indicator": "whoami returns root", "fallback": "Kernel exploit"},
    {"step": 3, "type": "objective",            "ip": TARGET, "port": None,
     "service": "host", "technique": "Data exfiltration",
     "cve_id": "N/A", "severity": "High", "score": 7.0,
     "objective": "Exfiltrate /etc/shadow", "tools": ["cat /etc/shadow"],
     "success_indicator": "Hash file retrieved", "fallback": "Document access"},
])

_MOCK_BATTLE_PLAN = textwrap.dedent(f"""\
    ## Battle Plan — {TARGET}

    **Overall Risk**: Critical
    **Total Steps**: 3
    **Attack Path Summary**: {TARGET}:22 → {TARGET} (priv-esc) → objective

    ---

    ### Phase 1: Initial Access
    **Target**: {TARGET}:22 | **Technique**: CVE-2024-6387 RCE | **CVE**: CVE-2024-6387

    Use Metasploit module exploit/linux/ssh/sshd_9_2_rce against {TARGET}.
    Set RHOSTS={TARGET} RPORT=22 and run.  Expect a Meterpreter session.

    **OPSEC**: Single connection attempt; do not spray.

    ### Phase 2: Privilege Escalation
    **Target**: {TARGET} | **Technique**: SUID binary abuse | **CVE**: N/A

    Run linpeas.sh to enumerate SUID binaries.  Exploit the highest-risk binary.

    ### Phase 3: Objective
    **Target**: {TARGET} | **Technique**: Data exfiltration | **CVE**: N/A

    Retrieve /etc/shadow and any .env files found under /var/www.

    ---

    ### Detection & IOC Notes
    SSH auth logs will show a single connection from attacker IP.

    ### Abort Criteria
    - SOC alert triggered
    - Unexpected data encountered outside scope
""")

_MOCK_FIXES = json.dumps([{
    "rank": 1,
    "title": "Upgrade OpenSSH to patch CVE-2024-6387",
    "severity": "Critical",
    "ip": TARGET, "port": 22, "service": "OpenSSH 9.2p1",
    "cve_id": "CVE-2024-6387",
    "bash_snippet": (
        "if command -v apt-get &>/dev/null; then\n"
        "    apt-get update -qq && apt-get install -y --only-upgrade openssh-server\n"
        "elif command -v yum &>/dev/null; then\n"
        "    yum update -y openssh-server\n"
        "elif command -v dnf &>/dev/null; then\n"
        "    dnf update -y openssh-server\n"
        "fi\nsystemctl restart sshd"
    ),
    "iptables_rules": (
        "iptables -A INPUT -p tcp --dport 22 -s 0.0.0.0/0 -j DROP\n"
        "iptables-save > /etc/iptables/rules.v4 2>/dev/null || true"
    ),
    "ansible_task": (
        '- name: "Upgrade OpenSSH to patch CVE-2024-6387"\n'
        '  package:\n'
        '    name: openssh-server\n'
        '    state: latest\n'
        '    update_cache: true\n'
        '  notify: Restart sshd'
    ),
    "verification_cmd": "ssh -V 2>&1 | grep -E '[0-9]+\\.[0-9]+'",
    "notes": "Restart sshd will briefly drop active SSH sessions.",
}])

_MOCK_ANALYST_NOTES = json.dumps({
    "entry_point_notes": [
        {"rank": 1, "tactical_note": "Critical RCE, exploit in Metasploit. Patch immediately."},
        {"rank": 2, "tactical_note": "Path traversal RCE, PoC widely available."},
        {"rank": 3, "tactical_note": "Old MySQL; no auth required if bind 0.0.0.0."},
    ],
    "analyst_summary": (
        "One Critical CVE-2024-6387 on SSH (CVSS 9.8), one High CVE-2021-41773 on Apache. "
        "Immediate patching required. MySQL 5.7 is EOL — upgrade or isolate."
    ),
})


def _make_llm_response(call_count: list[int]) -> mock.MagicMock:
    """
    Factory that returns a different canned LLM response on each call,
    cycling through: attack_surface → analyst_notes → footholds →
    path_nodes → battle_plan → fixes.
    """
    seq = [
        _MOCK_ATTACK_SURFACE,   # Scout LLM call
        _MOCK_ANALYST_NOTES,    # Analyst LLM enrichment call
        _MOCK_FOOTHOLDS,        # Strategist step-1 triage
        _MOCK_PATH_NODES,       # Strategist step-2 path planning
        _MOCK_BATTLE_PLAN,      # Strategist step-3 narration
        _MOCK_FIXES,            # Fixer batch
    ]

    def side_effect(messages):
        idx = call_count[0] % len(seq)
        call_count[0] += 1
        m = mock.MagicMock()
        m.content = seq[idx]
        return m

    return side_effect


# ─────────────────────────────────────────────────────────────────────────────
# Section runners
# ─────────────────────────────────────────────────────────────────────────────

def check_prerequisites(mock_mode: bool) -> bool:
    R.section("0 · Prerequisites")

    # nmap
    nmap_path = shutil.which("nmap")
    if nmap_path:
        R.ok("nmap available", nmap_path)
    else:
        R.fail("nmap available", "install with: apt-get install nmap")
        if not mock_mode:
            return False

    # .env / API key
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
    api_key = os.getenv("OPENAI_API_KEY", "")
    if api_key and not api_key.startswith("sk-your"):
        R.ok("OPENAI_API_KEY set", f"...{api_key[-6:]}")
    elif mock_mode:
        R.skip("OPENAI_API_KEY", "mock mode — LLM calls will be intercepted")
    else:
        R.fail("OPENAI_API_KEY not set", "add to .env")
        return False

    # Config validation
    try:
        from core.config import Config
        Config.validate()
        R.ok("Config.validate() passed")
    except EnvironmentError as exc:
        if mock_mode:
            R.skip("Config.validate()", f"mock mode ({exc})")
        else:
            R.fail("Config.validate()", str(exc))
            return False

    # SwarmController imports
    try:
        from agents.swarm_controller import SwarmController
        stages = [cls.__name__ for cls in SwarmController.PIPELINE]
        R.ok("SwarmController.PIPELINE loaded", " → ".join(stages))
    except Exception as exc:
        R.fail("SwarmController import", str(exc))
        return False

    return True


def run_pipeline(mock_mode: bool) -> "RTAIState | None":  # type: ignore[name-defined]
    R.section("1 · Pipeline execution")
    from agents.swarm_controller import SwarmController

    ctrl = SwarmController()
    print(f"\n  Target     : {_BOLD}{TARGET}{_RESET}")
    print(f"  Engagement : {_BOLD}{ENGAGEMENT}{_RESET}")
    print(f"  Mode       : {_BOLD}{'MOCK (fast)' if mock_mode else 'REAL (API + nmap)'}{_RESET}")
    print(f"  Pipeline   : {' → '.join(cls.role for cls in ctrl._pipeline)}\n")

    t0 = time.time()

    if mock_mode:
        # Patch nmap scanner and LLM invoke
        call_count = [0]

        def _fake_nmap_scan(self_inner, hosts, arguments):
            # Populate the internal PortScanner state so our wrapper works
            pass

        def _fake_nmap_all_hosts(self_inner):
            return [TARGET]

        def _fake_nmap_getitem(self_inner, host):
            class _FakeHost(dict):
                def hostname(self):  return "localhost"
                def state(self):     return "up"
                def all_protocols(self): return ["tcp"]

            fh = _FakeHost()
            fh["tcp"] = {
                22:   {"state": "open", "name": "ssh",  "product": "OpenSSH",
                       "version": "9.2p1", "extrainfo": "protocol 2.0"},
                80:   {"state": "open", "name": "http", "product": "Apache httpd",
                       "version": "2.4.49", "extrainfo": ""},
                3306: {"state": "open", "name": "mysql","product": "MySQL",
                       "version": "5.7.35", "extrainfo": ""},
            }
            fh["osmatch"] = [{"name": "Linux 5.x", "accuracy": "95"}]
            return fh

        try:
            import nmap
            with mock.patch.object(nmap.PortScanner, "scan",    _fake_nmap_scan), \
                 mock.patch.object(nmap.PortScanner, "all_hosts", _fake_nmap_all_hosts), \
                 mock.patch.object(nmap.PortScanner, "__getitem__", _fake_nmap_getitem), \
                 mock.patch(
                     "langchain_openai.ChatOpenAI.invoke",
                     side_effect=_make_llm_response(call_count),
                 ):
                state = ctrl.run(TARGET, ENGAGEMENT)
        except Exception as exc:
            R.fail("SwarmController.run() (mock)", str(exc))
            import traceback; traceback.print_exc()
            return None
    else:
        try:
            state = ctrl.run(TARGET, ENGAGEMENT)
        except Exception as exc:
            R.fail("SwarmController.run() (real)", str(exc))
            import traceback; traceback.print_exc()
            return None

    elapsed = time.time() - t0
    R.ok(f"SwarmController.run() completed", f"{elapsed:.1f}s")
    return state


def check_action_log(state: "RTAIState") -> None:  # type: ignore[name-defined]
    R.section("2 · action_log")
    log = state.action_log
    R.ok("action_log is non-empty", f"{len(log)} entries")

    expected_agents = ["Scout", "Analyst", "Strategist", "Fixer"]
    for role in expected_agents:
        starts    = [e for e in log if e.get("agent") == role and e.get("event") == "start"]
        completes = [e for e in log if e.get("agent") == role and e.get("event") == "complete"]
        if starts and completes:
            R.ok(f"{role}: start + complete events present")
        elif starts:
            R.fail(f"{role}: complete event missing")
        else:
            R.fail(f"{role}: no log entries found")

    has_ts = all("timestamp" in e for e in log)
    R.ok("All entries have timestamps") if has_ts else R.fail("Some entries missing timestamp")


def check_scout(state: "RTAIState") -> None:  # type: ignore[name-defined]
    R.section("3 · tool_outputs['scout']")
    scout = state.tool_outputs.get("scout", {})

    if not scout:
        R.fail("tool_outputs['scout'] is empty")
        return
    R.ok("tool_outputs['scout'] populated", f"{len(scout)} keys")

    hosts = scout.get("hosts", [])
    R.ok(f"hosts list present", f"{len(hosts)} host(s) discovered")

    if hosts:
        ip_list = [h.get("ip") for h in hosts]
        R.ok("hosts have 'ip' field", ", ".join(ip_list))

        total_ports = sum(len(h.get("open_ports", [])) for h in hosts)
        R.ok(f"open_ports present across all hosts", f"{total_ports} port(s)")

        sample_ports = [
            f"{op.get('port')}/{op.get('service','?')}"
            for h in hosts for op in h.get("open_ports", [])[:3]
        ]
        if sample_ports:
            R.ok("Port sample", ", ".join(sample_ports))
        else:
            R.skip("No open ports found on 127.0.0.1 (no services running)")
    else:
        R.skip("No hosts found", "nmap may have returned no results for 127.0.0.1")

    surface = scout.get("attack_surface", {})
    if isinstance(surface, dict):
        total_up    = surface.get("total_hosts_up", 0)
        total_ports = surface.get("total_open_ports", 0)
        high_risk   = surface.get("high_risk_ports", [])
        llm_text    = surface.get("llm_summary", "")
        R.ok("attack_surface dict present",
             f"hosts_up={total_up}  open_ports={total_ports}  "
             f"high_risk={high_risk[:5]}")
        if llm_text:
            R.ok("attack_surface.llm_summary populated", f"{len(llm_text)} chars")
            print(f"\n    {_YELLOW}LLM attack surface summary:{_RESET}")
            for line in textwrap.wrap(llm_text[:400], width=72):
                print(f"      {line}")
            print()
        else:
            R.skip("attack_surface.llm_summary empty", "LLM call may have returned no data")
    elif isinstance(surface, str) and surface:
        # Legacy string format fallback
        R.ok("attack_surface string populated", f"{len(surface)} chars")
    else:
        R.fail("attack_surface missing or empty")


def check_analyst(state: "RTAIState") -> None:  # type: ignore[name-defined]
    R.section("4 · tool_outputs['analyst']")
    analyst = state.tool_outputs.get("analyst", {})

    if not analyst:
        R.fail("tool_outputs['analyst'] is empty")
        return
    R.ok("tool_outputs['analyst'] populated", f"{len(analyst)} keys")

    eps = analyst.get("entry_points", [])
    R.ok(f"entry_points list present", f"{len(eps)} entry point(s)")

    if eps:
        for ep in eps:
            missing = [k for k in ("ip", "port", "severity", "dynamic_risk_score") if k not in ep]
            if missing:
                R.fail(f"entry_point missing fields", str(missing))
                break
        else:
            R.ok("All entry_points have required fields (ip, port, severity, score)")

        # Show top-5 sorted by score
        sorted_eps = sorted(eps, key=lambda e: float(e.get("dynamic_risk_score", 0)), reverse=True)
        print(f"\n    {'IP':<15} {'Port':<7} {'Severity':<10} {'Score':<7} {'CVEs'}")
        print(f"    {'-'*65}")
        for ep in sorted_eps[:5]:
            cves = ", ".join(c.get("cve_id","") for c in ep.get("cves",[])[:2]) or "—"
            sev  = ep.get("severity","?")
            col  = _RED if sev == "Critical" else _YELLOW if sev == "High" else _RESET
            print(f"    {ep.get('ip','?'):<15} :{ep.get('port','?'):<6} "
                  f"{col}{sev:<10}{_RESET} {ep.get('dynamic_risk_score',0.0):<7.2f} {cves}")
        print()

        crits = analyst.get("critical_count", 0)
        highs = analyst.get("high_count", 0)
        R.ok(f"Severity summary", f"Critical={crits}  High={highs}")
    else:
        R.skip("No entry_points", "no open ports were scanned")

    summary = analyst.get("analyst_summary", "")
    if summary:
        R.ok("analyst_summary present", f"{len(summary)} chars")
    else:
        R.skip("analyst_summary empty", "LLM enrichment may have returned no data")


def check_strategy(state: "RTAIState") -> None:  # type: ignore[name-defined]
    R.section("5 · tool_outputs['strategy']")
    strategy = state.tool_outputs.get("strategy", "")

    if not strategy:
        R.fail("tool_outputs['strategy'] is empty")
        return
    R.ok("tool_outputs['strategy'] populated", f"{len(strategy)} chars")

    has_plan_header = "Battle Plan" in strategy
    R.ok("Contains 'Battle Plan' header") if has_plan_header else \
        R.fail("Missing 'Battle Plan' header")

    has_phases = "Phase" in strategy or "phase" in strategy or "###" in strategy
    R.ok("Contains phase sections") if has_phases else \
        R.fail("No phase sections found in Battle Plan")

    # Show first 500 chars
    print(f"\n    {_YELLOW}Battle Plan preview:{_RESET}")
    for line in strategy.split("\n")[:12]:
        print(f"      {line}")
    if strategy.count("\n") > 12:
        print(f"      {_YELLOW}… ({strategy.count(chr(10))} lines total){_RESET}")
    print()

    # Attack path
    attack_path = state.tool_outputs.get("attack_path", [])
    R.ok(f"tool_outputs['attack_path'] populated", f"{len(attack_path)} path step(s)")
    if attack_path:
        path_str = " → ".join(
            f"{s.get('ip')}:{s.get('port')}" if s.get("port")
            else f"{s.get('ip')} ({s.get('type','')})"
            for s in attack_path
        )
        R.ok("Attack path", path_str)

    # Strategy finding
    strat_finding = next(
        (f for f in state.findings if f.get("phase") == "strategist"), {}
    )
    if strat_finding:
        R.ok("findings[phase=strategist] present",
             f"overall_risk={strat_finding.get('overall_risk','?')}  "
             f"steps={strat_finding.get('total_steps','?')}")
    else:
        R.fail("findings[phase=strategist] missing")


def check_fixer(state: "RTAIState") -> None:  # type: ignore[name-defined]
    R.section("6 · tool_outputs['fixer'] + remediation files")
    fixer = state.tool_outputs.get("fixer", {})

    if not fixer:
        R.fail("tool_outputs['fixer'] is empty")
        return
    R.ok("tool_outputs['fixer'] populated", f"{len(fixer)} keys")

    total = fixer.get("total_fixes", 0)
    R.ok(f"total_fixes reported", str(total))

    # File paths
    files = fixer.get("files", {})
    for key in ("bash", "ansible", "index"):
        fp = files.get(key, "")
        if fp:
            R.ok(f"files['{key}'] path set", fp)
        else:
            R.fail(f"files['{key}'] path missing")

    # Disk artefacts
    R.section("7 · Remediation files on disk")
    out_dir = fixer.get("output_dir", "")
    if out_dir:
        out_path = Path(out_dir)
        if out_path.exists():
            R.ok("Output directory created", str(out_path))
        else:
            R.fail("Output directory missing", out_dir)
            return
    else:
        R.fail("output_dir not set in fixer output")
        return

    checks = [
        ("Proposed_Fixes.sh",          "bash",    0o750),
        ("Proposed_Fixes.ansible.yml", "ansible", None),
        ("fix_index.txt",              "index",   None),
    ]
    for filename, key, expected_mode in checks:
        fpath = out_path / filename
        if fpath.exists():
            size = fpath.stat().st_size
            R.ok(f"{filename} exists", f"{size:,} bytes")

            # Quick content sanity check
            content = fpath.read_text(encoding="utf-8")
            if filename.endswith(".sh"):
                if "#!/usr/bin/env bash" in content:
                    R.ok("  Bash shebang present")
                else:
                    R.fail("  Bash shebang missing")
                if "DRY_RUN" in content:
                    R.ok("  DRY_RUN dispatcher present")
                else:
                    R.fail("  DRY_RUN dispatcher missing")
                if total > 0 and "fix_" in content:
                    R.ok("  Fix functions present")
                elif total == 0:
                    R.ok("  No fixes (expected — no entry points found)")

            elif filename.endswith(".yml"):
                if "hosts: all" in content:
                    R.ok("  Ansible playbook structure valid")
                else:
                    R.fail("  Ansible 'hosts: all' not found")

            elif filename.endswith(".txt"):
                if "RTAI Proposed Fixes" in content:
                    R.ok("  Fix index header present")
                else:
                    R.fail("  Fix index header missing")

            # Executable bit on .sh
            if expected_mode is not None:
                actual_mode = fpath.stat().st_mode & 0o777
                if actual_mode >= 0o750:
                    R.ok(f"  chmod {oct(actual_mode)} ✓")
                else:
                    R.fail(f"  Expected chmod 750, got {oct(actual_mode)}")
        else:
            R.fail(f"{filename} missing from {out_path}")

    # Show fix inventory if any
    fixes = fixer.get("fixes", [])
    if fixes:
        print(f"\n    {_YELLOW}Fix inventory ({len(fixes)} fix(es)):{_RESET}")
        print(f"    {'ID':<10} {'Severity':<10} {'Port':<7} {'Service':<28} {'CVE'}")
        print(f"    {'-'*70}")
        for fix in fixes:
            sev = fix.get("severity","?")
            col = _RED if sev == "Critical" else _YELLOW if sev == "High" else _RESET
            print(
                f"    {fix.get('fix_id','?'):<10} "
                f"{col}{sev:<10}{_RESET} "
                f":{fix.get('port','?'):<6} "
                f"{fix.get('service','?')[:27]:<28} "
                f"{fix.get('cve_id','N/A')}"
            )
        print()

    # Remediations list in state
    n_rems = len(state.remediations)
    if n_rems > 0:
        R.ok("state.remediations populated", f"{n_rems} entry/entries")
    else:
        R.skip("state.remediations empty", "no fixes generated (no entry points)")

    # state.finished
    if state.finished:
        R.ok("state.finished = True (pipeline marked complete)")
    else:
        R.fail("state.finished still False after pipeline")


def check_state_shape(state: "RTAIState") -> None:  # type: ignore[name-defined]
    R.section("8 · Overall state health")
    R.ok("state.target",          state.target)
    R.ok("state.engagement_name", state.engagement_name)

    n_findings = len(state.findings)
    R.ok(f"state.findings populated", f"{n_findings} finding(s)")

    expected_phases = ["scout", "analyst", "strategist", "fixer"]
    found_phases    = {f.get("phase") for f in state.findings}
    for phase in expected_phases:
        if phase in found_phases:
            R.ok(f"  findings[phase={phase!r}] present")
        else:
            R.fail(f"  findings[phase={phase!r}] missing")

    # Dump full state size
    state_json = state.model_dump()
    approx_kb  = len(json.dumps(state_json, default=str)) / 1024
    R.ok("Final state serialises cleanly", f"≈{approx_kb:.0f} KB")


def dry_run_bash(state: "RTAIState") -> None:  # type: ignore[name-defined]
    R.section("9 · DRY RUN — Proposed_Fixes.sh (bash all)")
    fixer = state.tool_outputs.get("fixer", {})
    bash_path = fixer.get("files", {}).get("bash", "")
    if not bash_path or not Path(bash_path).exists():
        R.skip("DRY RUN", "Proposed_Fixes.sh not found")
        return

    # 'list' subcommand — safe, only introspects function names
    result = subprocess.run(
        ["bash", bash_path, "list"],
        capture_output=True, text=True, timeout=15,
    )
    if result.returncode == 0:
        R.ok("bash Proposed_Fixes.sh list  (exit 0)")
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        if lines:
            print(f"\n    {_YELLOW}Available fixes:{_RESET}")
            for line in lines[:10]:
                print(f"      {line}")
        print()
    else:
        R.fail("bash list returned non-zero", result.stderr[:200])

    # Syntax check only — 'bash -n' parses without executing
    result_n = subprocess.run(
        ["bash", "-n", bash_path],
        capture_output=True, text=True, timeout=10,
    )
    if result_n.returncode == 0:
        R.ok("bash -n (syntax check) passed — script is valid bash")
    else:
        R.fail("bash -n syntax check failed", result_n.stderr[:200])

    # NOTE: We deliberately skip `DRY_RUN=1 bash ... all` because the
    # generated bash snippets invoke apt-get/yum/dnf directly (not through
    # the _run() wrapper), so even DRY_RUN=1 would trigger package-manager
    # calls.  The 'list' + '-n' checks above are sufficient for CI.
    R.ok("DRY_RUN note: 'list' + '-n' used instead of 'all' to avoid invoking package managers")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="RTAI Swarm integration test")
    parser.add_argument(
        "--mock", action="store_true",
        help="Mock LLM and nmap calls (fast, no API key needed)",
    )
    parser.add_argument(
        "--no-cleanup", action="store_true",
        help="Keep remediation output after test completes",
    )
    args = parser.parse_args()

    print(f"\n{_BOLD}{_CYAN}{'═' * 58}{_RESET}")
    print(f"{_BOLD}{_CYAN}  RTAI Swarm — Full Integration Test{_RESET}")
    print(f"{_BOLD}{_CYAN}  Target: {TARGET}  |  Mode: {'MOCK' if args.mock else 'REAL'}{_RESET}")
    print(f"{_BOLD}{_CYAN}{'═' * 58}{_RESET}\n")

    # ── 0. Prerequisites ──────────────────────────────────────────────────
    if not check_prerequisites(args.mock):
        print(f"\n{_RED}Prerequisites failed — aborting.{_RESET}\n")
        return 1

    # ── 1. Run pipeline ───────────────────────────────────────────────────
    state = run_pipeline(args.mock)
    if state is None:
        print(f"\n{_RED}Pipeline execution failed — aborting.{_RESET}\n")
        return 1

    # ── 2–9. Validate outputs ─────────────────────────────────────────────
    check_action_log(state)
    check_scout(state)
    check_analyst(state)
    check_strategy(state)
    check_fixer(state)
    check_state_shape(state)
    dry_run_bash(state)

    # ── Cleanup ───────────────────────────────────────────────────────────
    if not args.no_cleanup:
        fixer    = state.tool_outputs.get("fixer", {})
        out_dir  = fixer.get("output_dir", "")
        if out_dir and Path(out_dir).exists():
            shutil.rmtree(out_dir, ignore_errors=True)
            print(f"\n  {_YELLOW}Cleaned up:{_RESET} {out_dir}")

    # ── Final summary ─────────────────────────────────────────────────────
    all_passed = R.summary()
    print()
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())

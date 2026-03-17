"""
agents/fixer_agent.py

Fixer agent: converts every Exploitable Entry Point from the Analyst and
every step in the Strategist's Battle Plan into executable, localised
remediation scripts.

Pipeline
--------
1. **Data extraction**
   Reads ``tool_outputs["analyst"]["entry_points"]`` (AnalystAgent structured
   output) or falls back to ``findings[phase=analyst]`` and
   ``findings[phase=remediation]`` for compatibility with the legacy pipeline.
   Reads the Strategist's attack plan from ``tool_outputs["strategy"]``.

2. **Fix generation** (LLM, batched)
   Entry points are processed in batches of ``BATCH_SIZE`` (default 5).
   For each batch the LLM returns a JSON array where every element contains:
   - ``bash_snippet``   — copy-paste ready Bash commands (apt/yum/dnf auto-detected)
   - ``iptables_rules`` — firewall rule(s) to isolate the exposed service
   - ``ansible_task``   — YAML task block for Ansible automation
   - ``verification_cmd`` — one-liner to confirm the fix was applied
   If the LLM response cannot be parsed, ``_fallback_fix()`` generates a
   template-based fix from port/product hints.

3. **Script assembly**
   Fixes are sorted Critical → High → Medium → Low, then assembled into:

   - ``Proposed_Fixes.sh``         — Bash script with a function-per-fix layout
                                       and a dispatcher supporting ``all``,
                                       ``fix_001``, ``list``, and ``DRY_RUN=1``.
   - ``Proposed_Fixes.ansible.yml`` — Complete Ansible playbook (one task per fix).
   - ``fix_index.txt``              — Human-readable summary table.

4. **File output**
   Files are written to::

       remediation/<engagement_name>_<YYYY-MM-DD>/
           Proposed_Fixes.sh
           Proposed_Fixes.ansible.yml
           fix_index.txt

   The path is stored in ``state.tool_outputs["fixer"]["output_dir"]``.
   Write errors are collected and non-fatal.
"""
from __future__ import annotations

import datetime
import json
import re
import textwrap
from pathlib import Path
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from agents.base_agent import BaseAgent
from core.config import Config
from core.state import RTAIState


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0, "high": 1, "medium": 2, "low": 3,
}

# ---------------------------------------------------------------------------
# ServiceImpactAnalyzer — high-traffic port classification
# ---------------------------------------------------------------------------

# Ports classified as "High Traffic": unexpected restarts on these services
# during business hours can impact many users.  Service-restart commands
# in fixes for these ports are wrapped in a maintenance-window guard unless
# MAINTENANCE_OVERRIDE=1 is set.
_HIGH_TRAFFIC_PORTS: frozenset[int] = frozenset({
    53,    # DNS — any resolver interruption breaks name resolution fleet-wide
    80,    # HTTP — production web traffic
    443,   # HTTPS — production web traffic (TLS)
    8080,  # HTTP alternate — common app servers
    8443,  # HTTPS alternate
})

# Port → package hints for template-based fallback scripts.
# "deb" = Debian/Ubuntu package name, "rpm" = RHEL/CentOS/Fedora package name.
_PORT_HINTS: dict[int, dict[str, str]] = {
    21:    {"deb": "vsftpd",           "rpm": "vsftpd",            "svc": "vsftpd"},
    22:    {"deb": "openssh-server",   "rpm": "openssh-server",    "svc": "sshd"},
    23:    {"deb": "telnetd",          "rpm": "telnet-server",     "svc": "telnet"},
    25:    {"deb": "postfix",          "rpm": "postfix",           "svc": "postfix"},
    53:    {"deb": "bind9",            "rpm": "bind",              "svc": "named"},
    80:    {"deb": "apache2",          "rpm": "httpd",             "svc": "apache2"},
    443:   {"deb": "apache2",          "rpm": "httpd",             "svc": "apache2"},
    445:   {"deb": "samba",            "rpm": "samba",             "svc": "smb"},
    1433:  {"deb": "mssql-server",     "rpm": "mssql-server",      "svc": "mssql-server"},
    3306:  {"deb": "mysql-server",     "rpm": "mysql-server",      "svc": "mysql"},
    3389:  {"deb": "xrdp",             "rpm": "xrdp",              "svc": "xrdp"},
    5432:  {"deb": "postgresql",       "rpm": "postgresql-server", "svc": "postgresql"},
    5900:  {"deb": "tigervnc-server",  "rpm": "tigervnc-server",   "svc": "vncserver"},
    5985:  {"deb": "winrm",            "rpm": "winrm",             "svc": "winrm"},
    6379:  {"deb": "redis-server",     "rpm": "redis",             "svc": "redis"},
    8080:  {"deb": "apache2",          "rpm": "httpd",             "svc": "apache2"},
    8443:  {"deb": "apache2",          "rpm": "httpd",             "svc": "apache2"},
    9200:  {"deb": "elasticsearch",    "rpm": "elasticsearch",     "svc": "elasticsearch"},
    27017: {"deb": "mongodb-org",      "rpm": "mongodb-org",       "svc": "mongod"},
}


# ---------------------------------------------------------------------------
# Safety-filter patterns — operations that may disrupt live systems
# ---------------------------------------------------------------------------

# Reboot / power-off commands
_REBOOT_RE = re.compile(
    r"\b(reboot|shutdown|halt|poweroff|init\s+6"
    r"|systemctl\s+(?:reboot|poweroff|halt))\b",
    re.IGNORECASE,
)

# Services whose unexpected restart / stop could break connectivity or security
_CRITICAL_SVCS: frozenset[str] = frozenset({
    "dnsmasq", "hostapd", "sshd", "ssh", "networking",
    "network-manager", "networkmanager", "firewalld", "iptables",
    "nftables", "wpa_supplicant", "systemd-networkd",
    "systemd-resolved", "avahi-daemon",
})

# Match  "systemctl restart|stop <svc>"  or  "service <svc> restart|stop"
_SVC_RESTART_RE = re.compile(
    r"systemctl\s+(?:restart|stop)\s+(\S+)"
    r"|service\s+(\S+)\s+(?:restart|stop)",
    re.IGNORECASE,
)

# Firewall changes that flush all rules or set a blanket DROP default policy
_FIREWALL_DISRUPTIVE_RE = re.compile(
    r"iptables\s+(?:-P\s+(?:INPUT|OUTPUT|FORWARD)\s+DROP|-F\b|--flush\b)"
    r"|ip6tables\s+(?:-P\s+(?:INPUT|OUTPUT|FORWARD)\s+DROP|-F\b)"
    r"|ufw\s+(?:--force\s+)?(?:enable|default\s+deny)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Fixer agent
# ---------------------------------------------------------------------------

class FixerAgent(BaseAgent):
    """
    Fixer agent: generates localised remediation scripts for every
    Exploitable Entry Point and writes them to ``remediation/``.

    Compatible with the ``SwarmController`` pipeline (reads Strategist +
    Analyst output) and standalone usage via ``BaseAgent.execute()``.
    """

    role = "Fixer"
    goal = (
        "Convert every identified vulnerability into an executable, localised "
        "remediation script.  Produce Bash patch commands, IPTables firewall "
        "rules, and Ansible tasks.  Save all scripts to the remediation/ folder "
        "for immediate sysadmin review and deployment."
    )

    #: Number of entry points sent to the LLM per request (avoids token limits).
    BATCH_SIZE: int = 5

    # ------------------------------------------------------------------
    # BaseAgent interface
    # ------------------------------------------------------------------

    def run(self, state: RTAIState) -> dict[str, Any]:
        now = datetime.datetime.now()
        engagement = state.engagement_name or "RTAI_Engagement"

        entry_points = self._extract_entry_points(state)
        strategy = self._extract_strategy(state)

        # Generate and sort fixes
        if entry_points:
            fixes = self._generate_all_fixes(entry_points, strategy, state.target)
            fixes.sort(
                key=lambda f: _SEVERITY_ORDER.get(
                    f.get("severity", "").lower(), 99
                )
            )
        else:
            fixes = []

        # Assign canonical IDs after sorting
        for i, fix in enumerate(fixes, 1):
            fix["fix_id"] = f"fix_{i:03d}"

        # Safety filter — flag fixes that may disrupt live services
        for fix in fixes:
            disruptive, reasons = self._safety_filter(fix)
            fix["potentially_disruptive"] = disruptive
            fix["disruption_reasons"] = reasons

        # Assemble and persist
        bash_src     = self._assemble_bash(fixes, engagement, state.target, now)
        ansible_src  = self._assemble_ansible(fixes, engagement, state.target, now)
        index_txt    = self._assemble_index(fixes, engagement, state.target, now)
        output_dir, write_errors = self._save_to_disk(
            bash_src, ansible_src, index_txt, engagement, now
        )

        return self._build_partial(fixes, output_dir, write_errors, state.target)

    # ------------------------------------------------------------------
    # Data extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_entry_points(state: RTAIState) -> list[dict[str, Any]]:
        """
        Extract ranked entry points from state.

        Priority
        --------
        1. ``tool_outputs["analyst"]["entry_points"]`` (AnalystAgent)
        2. ``findings[phase=analyst]["entry_points"]`` (findings fallback)
        3. ``findings[phase=remediation]`` remediations list (legacy pipeline)
        """
        # 1. AnalystAgent structured output
        analyst = state.tool_outputs.get("analyst", {})
        if analyst.get("entry_points"):
            return analyst["entry_points"]

        # 2. Findings fallback
        analyst_finding = next(
            (f for f in state.findings if f.get("phase") == "analyst"
             and f.get("entry_points")), {}
        )
        if analyst_finding.get("entry_points"):
            return analyst_finding["entry_points"]

        # 3. Legacy RemediationAgent findings → convert to minimal entry-point shape
        rem_finding = next(
            (f for f in state.findings if f.get("phase") == "remediation"), {}
        )
        legacy_rems: list[dict[str, Any]] = rem_finding.get("remediations", [])
        if legacy_rems:
            return [
                {
                    "rank": i + 1,
                    "ip": rem_finding.get("target", state.target),
                    "port": 0,
                    "protocol": "tcp",
                    "service": r.get("service", "unknown"),
                    "product": r.get("service", ""),
                    "version": "",
                    "severity": r.get("risk_level", "Medium"),
                    "dynamic_risk_score": 5.0,
                    "cves": [{"cve_id": r.get("cve", "N/A"), "cvss_v3": 0.0,
                              "description": "", "exploit_available": False}],
                    "exploit_available": False,
                    "risk_hint": "",
                    "analyst_notes": "\n".join(r.get("steps", [])),
                }
                for i, r in enumerate(legacy_rems)
            ]

        return []

    @staticmethod
    def _extract_strategy(state: RTAIState) -> str:
        """Return the Strategist's battle plan text, or an empty string."""
        # Prefer structured tool output
        strategy = state.tool_outputs.get("strategy", "")
        if strategy:
            return strategy

        # Fall back to findings
        strat_finding = next(
            (f for f in state.findings if f.get("phase") == "strategist"), {}
        )
        return strat_finding.get("attack_plan", "")

    # ------------------------------------------------------------------
    # LLM fix generation
    # ------------------------------------------------------------------

    def _generate_all_fixes(
        self,
        entry_points: list[dict[str, Any]],
        strategy: str,
        target: str,
    ) -> list[dict[str, Any]]:
        """Process entry points in batches; fall back to templates on failure."""
        all_fixes: list[dict[str, Any]] = []
        for i in range(0, len(entry_points), self.BATCH_SIZE):
            batch = entry_points[i : i + self.BATCH_SIZE]
            batch_fixes = self._generate_batch(batch, strategy, target)
            all_fixes.extend(batch_fixes)
        return all_fixes

    def _generate_batch(
        self,
        batch: list[dict[str, Any]],
        strategy: str,
        target: str,
    ) -> list[dict[str, Any]]:
        """
        Ask the LLM to generate fix scripts for one batch of entry points.

        Returns a list of fix dicts.  Falls back to ``_fallback_fix()`` for
        any entry point whose LLM response is missing or malformed.
        """
        condensed = [
            {
                "rank": ep.get("rank", 0),
                "ip": ep.get("ip", target),
                "port": ep.get("port", 0),
                "service": f"{ep.get('product','')} {ep.get('version','')}".strip()
                           or ep.get("service", "unknown"),
                "severity": ep.get("severity", "Medium"),
                "score": ep.get("dynamic_risk_score", 0.0),
                "cves": [c.get("cve_id", "") for c in ep.get("cves", [])[:2]],
                "os_context": ep.get("os_context", "Linux"),
                "analyst_notes": ep.get("analyst_notes", ""),
            }
            for ep in batch
        ]

        ansible_mode = Config.REMEDIATION_FORMAT == "ansible"
        if ansible_mode:
            remediation_instructions = (
                "For EACH entry point return a JSON array element "
                "(one element per entry point, same order). "
                "REMEDIATION_FORMAT=ansible: the ansible_task field is the PRIMARY "
                "deliverable and must be a complete, production-ready Ansible task "
                "block with proper YAML indentation. "
                "Use this EXACT schema — no markdown fences, no extra keys:\n"
                "[\n"
                "  {\n"
                '    "rank": <integer from input>,\n'
                '    "title": "<imperative fix title, ≤ 60 chars>",\n'
                '    "severity": "<Critical|High|Medium|Low>",\n'
                '    "ip": "<ip from input>",\n'
                '    "port": <port number>,\n'
                '    "service": "<product version from input>",\n'
                '    "cve_id": "<primary CVE or N/A>",\n'
                '    "bash_snippet": "<minimal bash fallback; detect apt vs yum/dnf>",\n'
                '    "iptables_rules": "<iptables command(s) or empty string>",\n'
                '    "ansible_task": "<REQUIRED: full Ansible task YAML starting with '
                "- name:; use package/service/lineinfile/shell modules as needed; "
                'include become: true at task level>",\n'
                '    "verification_cmd": "<single shell command to confirm fix>",\n'
                '    "notes": "<1 sentence: caveats, restart warnings, rollback tip>"\n'
                "  }\n"
                "]\n\n"
                "Ansible task rules:\n"
                "- Each task MUST start with '- name:' and include correct 2-space indentation.\n"
                "- Prefer 'ansible.builtin.package' for package installs (auto-detects apt/yum/dnf).\n"
                "- Use 'ansible.builtin.service' with state: restarted where needed.\n"
                "- Use 'ansible.builtin.iptables' for firewall rules instead of raw shell.\n"
                "- Do not invent CVEs; use cve_id from the input list.\n"
                "- Stay within authorised scope."
            )
        else:
            remediation_instructions = (
                "For EACH entry point return a JSON array element "
                "(one element per entry point, same order). "
                "Use this EXACT schema — no markdown fences, no extra keys:\n"
                "[\n"
                "  {\n"
                '    "rank": <integer from input>,\n'
                '    "title": "<imperative fix title, ≤ 60 chars>",\n'
                '    "severity": "<Critical|High|Medium|Low>",\n'
                '    "ip": "<ip from input>",\n'
                '    "port": <port number>,\n'
                '    "service": "<product version from input>",\n'
                '    "cve_id": "<primary CVE or N/A>",\n'
                '    "bash_snippet": "<multi-line bash; detect apt vs yum/dnf; '
                'restart service; NO shebang line>",\n'
                '    "iptables_rules": "<iptables command(s) to isolate the port, '
                'or empty string if not applicable>",\n'
                '    "ansible_task": "<valid YAML: one or more Ansible task blocks '
                'starting with - name:>",\n'
                '    "verification_cmd": "<single shell command to confirm fix>",\n'
                '    "notes": "<1 sentence: caveats, restart warnings, rollback tip>"\n'
                "  }\n"
                "]\n\n"
                "Rules:\n"
                "- bash_snippet must use 'if command -v apt-get' / 'elif command -v "
                "yum' / 'elif command -v dnf' to auto-detect the package manager.\n"
                "- iptables_rules should include both the rule and "
                "'iptables-save > /etc/iptables/rules.v4 2>/dev/null || true'.\n"
                "- ansible_task must be valid YAML with correct indentation.\n"
                "- Do not invent CVEs; use cve_id from the input list.\n"
                "- Stay within authorised scope."
            )

        messages = [
            SystemMessage(content=self._system_prompt()),
            HumanMessage(
                content=(
                    f"Target: {target}\n\n"
                    + (f"Battle plan from Strategist:\n{strategy[:1500]}\n\n"
                       if strategy else "")
                    + "Entry points requiring remediation:\n"
                    f"```json\n{json.dumps(condensed, indent=2)}\n```\n\n"
                    + remediation_instructions
                )
            ),
        ]

        raw_fixes: list[dict[str, Any]] = []
        try:
            response = self.llm.invoke(messages)
            raw_fixes = json.loads(response.content)
            if not isinstance(raw_fixes, list):
                raise ValueError("LLM returned non-list JSON")
        except Exception:  # noqa: BLE001
            # Entire batch failed — fall back for every entry point
            return [self._fallback_fix(ep) for ep in batch]

        # Align returned fixes with input batch (by rank, fill gaps with fallback)
        rank_to_fix: dict[int, dict[str, Any]] = {
            f.get("rank", 0): f for f in raw_fixes if isinstance(f, dict)
        }
        result: list[dict[str, Any]] = []
        for ep in batch:
            rank = ep.get("rank", 0)
            fix = rank_to_fix.get(rank)
            if fix and fix.get("bash_snippet"):
                # Merge rich analyst data back in
                fix.setdefault("exploit_available", ep.get("exploit_available", False))
                fix.setdefault("dynamic_risk_score", ep.get("dynamic_risk_score", 0.0))
                result.append(fix)
            else:
                result.append(self._fallback_fix(ep))
        return result

    @staticmethod
    def _fallback_fix(ep: dict[str, Any]) -> dict[str, Any]:
        """
        Generate a template-based fix when the LLM call fails or returns
        unusable output.  Always produces runnable (if conservative) scripts.
        """
        port: int = ep.get("port", 0)
        ip: str = ep.get("ip", "TARGET_IP")
        severity: str = ep.get("severity", "Medium")
        service: str = (
            f"{ep.get('product','')} {ep.get('version','')}".strip()
            or ep.get("service", "unknown service")
        )
        cve = next(
            (c.get("cve_id", "N/A") for c in ep.get("cves", []) if c.get("cve_id")),
            "N/A",
        )
        hints = _PORT_HINTS.get(port, {})
        pkg_deb = hints.get("deb", "")
        pkg_rpm = hints.get("rpm", "")
        svc_name = hints.get("svc", "")

        # --- Bash snippet ------------------------------------------------
        if pkg_deb:
            bash = textwrap.dedent(f"""\
                # Update {service} package
                if command -v apt-get &>/dev/null; then
                    apt-get update -qq
                    apt-get install -y --only-upgrade {pkg_deb}
                elif command -v yum &>/dev/null; then
                    yum update -y {pkg_rpm}
                elif command -v dnf &>/dev/null; then
                    dnf update -y {pkg_rpm}
                fi
                {"# Restart service" if svc_name else ""}
                {"systemctl restart " + svc_name if svc_name else ""}
            """).rstrip()
        else:
            bash = (
                f"# No package hint for port {port} — manually update {service}\n"
                f"echo 'Action required: update {service} on {ip}:{port}'"
            )

        # --- IPTables rule -----------------------------------------------
        if port:
            ipt = textwrap.dedent(f"""\
                # Block external access to port {port} (temporary mitigation)
                iptables -A INPUT -p tcp --dport {port} -j DROP
                iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
            """).rstrip()
        else:
            ipt = ""

        # --- Ansible task ------------------------------------------------
        if pkg_deb:
            ansible = textwrap.dedent(f"""\
                - name: "Update {pkg_deb} to remediate {cve}"
                  package:
                    name: "{pkg_deb}"
                    state: latest
                    update_cache: true
                  {"notify: Restart " + svc_name if svc_name else ""}
            """).rstrip()
        else:
            ansible = (
                f"- name: \"Manually remediate {service} on port {port}\"\n"
                f"  debug:\n"
                f"    msg: 'Review and patch {service} — CVE: {cve}'"
            )

        return {
            "rank": ep.get("rank", 0),
            "title": f"Patch {service or f'port {port}'} ({cve})",
            "severity": severity,
            "ip": ip,
            "port": port,
            "service": service,
            "cve_id": cve,
            "bash_snippet": bash,
            "iptables_rules": ipt,
            "ansible_task": ansible,
            "verification_cmd": (
                f"systemctl is-active {svc_name}" if svc_name
                else f"nmap -p {port} {ip}"
            ),
            "notes": "Template-based fix — review before applying.",
            "exploit_available": ep.get("exploit_available", False),
            "dynamic_risk_score": ep.get("dynamic_risk_score", 0.0),
        }

    # ------------------------------------------------------------------
    # Safety filter
    # ------------------------------------------------------------------

    @staticmethod
    def _safety_filter(fix: dict[str, Any]) -> tuple[bool, list[str]]:
        """
        Inspect a fix's scripts for potentially disruptive operations.

        Checks
        ------
        1. Reboot / shutdown / halt / poweroff commands.
        2. ``systemctl restart|stop`` or ``service ... restart|stop`` targeting
           critical infrastructure services (dnsmasq, hostapd, sshd, etc.).
        3. iptables / ip6tables / ufw commands that flush all rules or set a
           blanket DROP default policy — these can drop all active connections.

        Returns
        -------
        ``(is_disruptive, reasons)`` where *reasons* is a list of human-readable
        strings explaining why the fix was flagged.
        """
        combined = " ".join([
            fix.get("bash_snippet",   "") or "",
            fix.get("iptables_rules", "") or "",
            fix.get("ansible_task",   "") or "",
        ])
        reasons: list[str] = []

        # 1. Reboot / power-off
        if _REBOOT_RE.search(combined):
            reasons.append("Contains a reboot or shutdown command")

        # 2. Critical service restart / stop
        seen_svcs: set[str] = set()
        for m in _SVC_RESTART_RE.finditer(combined):
            # group 1 → systemctl form, group 2 → service form
            raw = (m.group(1) or m.group(2) or "").lower().rstrip(";").strip()
            if raw in _CRITICAL_SVCS and raw not in seen_svcs:
                reasons.append(f"Restarts or stops critical service: {raw}")
                seen_svcs.add(raw)

        # 3. Disruptive firewall changes
        if _FIREWALL_DISRUPTIVE_RE.search(combined):
            reasons.append(
                "Modifies firewall default policy or flushes all rules "
                "(may drop existing connections)"
            )

        return bool(reasons), reasons

    # ------------------------------------------------------------------
    # ServiceImpactAnalyzer helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_high_traffic_port(port: int) -> bool:
        """Return True if *port* serves high-traffic / user-facing traffic."""
        return port in _HIGH_TRAFFIC_PORTS

    @staticmethod
    def _wrap_high_traffic_restart(bash_snippet: str, service_name: str) -> str:
        """
        Wrap any ``systemctl restart`` / ``service restart`` commands for a
        high-traffic service in a maintenance-window guard.

        The guard allows the restart only between 02:00 and 05:00 (local
        time) unless ``MAINTENANCE_OVERRIDE=1`` is set by the operator.

        Parameters
        ----------
        bash_snippet:
            The original bash commands for this fix.
        service_name:
            Service name (e.g. ``"apache2"``, ``"named"``).  Used to build
            a targeted regex so unrelated restarts are not wrapped.

        Returns
        -------
        Modified bash snippet with the restart guarded.
        """
        import re

        # Build a pattern that matches restart/stop commands for *this* service
        svc_re = re.compile(
            rf"(systemctl\s+(?:restart|stop)\s+{re.escape(service_name)}"
            rf"|service\s+{re.escape(service_name)}\s+(?:restart|stop))",
            re.IGNORECASE,
        )

        def _replace(m: re.Match) -> str:
            cmd = m.group(0).strip()
            return textwrap.dedent(f"""\
                # ServiceImpactAnalyzer: high-traffic service — restrict restart to
                # maintenance window (02:00–05:00) unless MAINTENANCE_OVERRIDE=1
                if [ "${{MAINTENANCE_OVERRIDE:-0}}" = "1" ]; then
                    {cmd}
                elif [ "$(date +%H)" -ge 02 ] && [ "$(date +%H)" -lt 05 ]; then
                    {cmd}
                else
                    echo "WARNING: Restart of '{service_name}' deferred." \\
                         "Run during 02:00-05:00 or set MAINTENANCE_OVERRIDE=1."
                fi""")

        return svc_re.sub(_replace, bash_snippet)

    # ------------------------------------------------------------------
    # Script assembly
    # ------------------------------------------------------------------

    @staticmethod
    def _assemble_bash(
        fixes: list[dict[str, Any]],
        engagement: str,
        target: str,
        ts: datetime.datetime,
    ) -> str:
        """
        Assemble ``Proposed_Fixes.sh`` — a Bash script with one function per
        fix and a dispatcher for selective or full execution.

        Features
        --------
        - ``DRY_RUN=1`` mode prints commands without running them.
        - ``bash Proposed_Fixes.sh list`` shows all available fix IDs.
        - ``bash Proposed_Fixes.sh fix_001`` runs a single fix.
        - ``bash Proposed_Fixes.sh all`` runs every fix in severity order.
        """
        header = textwrap.dedent(f"""\
            #!/usr/bin/env bash
            # ==========================================================================
            # RTAI Proposed Fixes
            # Engagement : {engagement}
            # Target     : {target}
            # Generated  : {ts.strftime('%Y-%m-%d %H:%M:%S')}
            # Fixes      : {len(fixes)} item(s)
            # ==========================================================================
            #
            # ⚠  IMPORTANT — READ BEFORE RUNNING
            # --------------------------------------------------------------------------
            # This script was generated by an automated security assessment tool.
            # • Review EVERY section before executing anything.
            # • Test in a staging environment first.
            # • Back up all configuration files before making changes.
            # • Some fixes will restart services and may cause brief outages.
            #
            # Usage:
            #   DRY_RUN=1 bash Proposed_Fixes.sh all       # preview without applying
            #   bash Proposed_Fixes.sh all                  # apply all fixes in order
            #   bash Proposed_Fixes.sh fix_001              # apply a single fix
            #   bash Proposed_Fixes.sh list                 # list available fixes
            # ==========================================================================
            set -uo pipefail

            DRY_RUN="${{DRY_RUN:-0}}"

            _run() {{
                if [[ "$DRY_RUN" == "1" ]]; then
                    printf '\\033[0;33m[DRY-RUN]\\033[0m  %s\\n' "$*"
                else
                    eval "$@"
                fi
            }}

            _section() {{ printf '\\n\\033[1;34m══ %s ══\\033[0m\\n' "$*"; }}
            _ok()      {{ printf '\\033[0;32m  ✔ %s\\033[0m\\n' "$*"; }}
            _warn()    {{ printf '\\033[0;33m  ⚠ %s\\033[0m\\n' "$*"; }}
            _err()     {{ printf '\\033[0;31m  ✘ %s\\033[0m\\n' "$*" >&2; }}

        """)

        if not fixes:
            no_fixes = textwrap.dedent("""\
                echo "No exploitable entry points were identified — no fixes to apply."
                exit 0
            """)
            return header + no_fixes

        func_blocks: list[str] = []
        for fix in fixes:
            fid      = fix.get("fix_id", "fix_000")
            title    = fix.get("title", "Untitled fix")
            sev      = fix.get("severity", "Unknown").upper()
            ip       = fix.get("ip", target)
            port     = fix.get("port", 0)
            service  = fix.get("service", "")
            cve      = fix.get("cve_id", "N/A")
            score    = fix.get("dynamic_risk_score", 0.0)
            bash_snip = (fix.get("bash_snippet") or "").strip()
            ipt_rules = (fix.get("iptables_rules") or "").strip()
            verify    = (fix.get("verification_cmd") or "").strip()
            notes     = (fix.get("notes") or "").strip()

            # ServiceImpactAnalyzer: wrap service restarts for high-traffic ports
            # in a maintenance-window guard so they only run during 02:00–05:00.
            if bash_snip and FixerAgent._is_high_traffic_port(port):
                hints = _PORT_HINTS.get(port, {})
                svc_name_hint = hints.get("svc", "")
                if svc_name_hint:
                    bash_snip = FixerAgent._wrap_high_traffic_restart(
                        bash_snip, svc_name_hint
                    )

            # Indent the LLM / template snippet inside the function body
            indented_bash = "\n".join(
                f"    {line}" for line in bash_snip.splitlines()
            ) if bash_snip else "    echo 'No bash commands generated for this fix.'"

            indented_ipt = (
                "\n".join(f"    {line}" for line in ipt_rules.splitlines())
                if ipt_rules else ""
            )

            block = f"""\
# ── [{sev}] {fid}: {title}
# Target  : {ip}:{port}  |  Service: {service}  |  CVE: {cve}  |  Score: {score}
{fid}() {{
    _section "[{sev}] {fid}: {title}"
"""
            if notes:
                block += f'    _warn "{notes}"\n'

            block += "\n    # ── Patch / update ──\n"
            block += indented_bash + "\n"

            if indented_ipt:
                block += "\n    # ── IPTables firewall rule ──\n"
                block += indented_ipt + "\n"

            if verify:
                block += f'\n    # ── Verification ──\n    _ok "Verify: {verify}"\n'
                # Run verify command and capture output safely
                block += (
                    f'    if _verify_out=$({verify} 2>&1); then\n'
                    f'        _ok "Check passed: ${{_verify_out}}"\n'
                    f'    else\n'
                    f'        _warn "Check returned non-zero — manual review advised"\n'
                    f'    fi\n'
                )

            block += "}\n"
            func_blocks.append(block)

        # Build verification summary comment
        verify_lines = []
        for fix in fixes:
            fid  = fix.get("fix_id", "?")
            vcmd = fix.get("verification_cmd", "")
            if vcmd:
                verify_lines.append(f"#   {fid}: {vcmd}")

        dispatcher = textwrap.dedent(f"""\
            # ---------------------------------------------------------------------------
            # Dispatcher
            # ---------------------------------------------------------------------------

            _list_fixes() {{
                echo "Available fixes (severity order):"
                declare -F | awk '{{print $3}}' | grep '^fix_' | sort | while read -r fn; do
                    echo "  $fn"
                done
            }}

            case "${{1:-}}" in
                all)
                    for fn in $(declare -F | awk '{{print $3}}' | grep '^fix_' | sort); do
                        "$fn" || _warn "$fn failed — continuing with next fix"
                    done
                    ;;
                fix_*)
                    if declare -F "${{1}}" > /dev/null 2>&1; then
                        "${{1}}"
                    else
                        _err "Unknown fix: ${{1}}"
                        _list_fixes
                        exit 1
                    fi
                    ;;
                list)
                    _list_fixes
                    ;;
                *)
                    echo "Usage: [DRY_RUN=1] $0 [all | fix_001 | fix_002 | ... | list]"
                    echo ""
                    _list_fixes
                    ;;
            esac
        """)

        return header + "\n".join(func_blocks) + "\n" + dispatcher

    @staticmethod
    def _assemble_ansible(
        fixes: list[dict[str, Any]],
        engagement: str,
        target: str,
        ts: datetime.datetime,
    ) -> str:
        """
        Assemble ``Proposed_Fixes.ansible.yml`` — a complete Ansible playbook.

        Usage::

            ansible-playbook Proposed_Fixes.ansible.yml -i "<target>," -K
            ansible-playbook Proposed_Fixes.ansible.yml -i inventory.ini --tags critical
        """
        header = textwrap.dedent(f"""\
            ---
            # ==========================================================================
            # RTAI Proposed Fixes — Ansible Playbook
            # Engagement : {engagement}
            # Target     : {target}
            # Generated  : {ts.strftime('%Y-%m-%d %H:%M:%S')}
            #
            # Usage:
            #   ansible-playbook Proposed_Fixes.ansible.yml -i "{target}," -K
            #   ansible-playbook Proposed_Fixes.ansible.yml -i inventory.ini \\
            #       --tags critical
            # ==========================================================================

            - name: "RTAI Remediation Playbook — {engagement}"
              hosts: all
              become: true
              gather_facts: true

              tasks:
        """)

        if not fixes:
            return header + textwrap.dedent("""\
                    - name: "No fixes required"
                      debug:
                        msg: "No exploitable entry points were identified."
            """)

        task_blocks: list[str] = []
        for fix in fixes:
            fid     = fix.get("fix_id", "fix_000")
            title   = fix.get("title", "Untitled fix")
            sev     = fix.get("severity", "Unknown").lower()
            cve     = fix.get("cve_id", "N/A")
            ansible = (fix.get("ansible_task") or "").strip()

            task_blocks.append(
                f"        # ── [{sev.upper()}] {fid}: {title} ──"
            )

            if ansible:
                # Indent the task block to sit inside the tasks: list at 8 spaces
                indented = "\n".join(
                    f"        {line}" for line in ansible.splitlines()
                )
                # Inject tags after the first "- name:" line
                if "- name:" in indented:
                    lines = indented.splitlines()
                    for idx, line in enumerate(lines):
                        if "- name:" in line:
                            tag_line = (
                                f"          tags: [{sev}, {fid}, "
                                f'"{cve.replace(chr(34), chr(39))}"]'
                            )
                            lines.insert(idx + 1, tag_line)
                            break
                    indented = "\n".join(lines)
                task_blocks.append(indented)
            else:
                task_blocks.append(textwrap.dedent(f"""\
                          - name: "[{fid}] {title}"
                            debug:
                              msg: "No Ansible task generated — apply manually."
                            tags: [{sev}, {fid}]
                """).rstrip())

            task_blocks.append("")

        # Collect service names for handlers
        svc_names: list[str] = []
        for fix in fixes:
            port = fix.get("port", 0)
            svc = _PORT_HINTS.get(port, {}).get("svc", "")
            if svc and svc not in svc_names:
                svc_names.append(svc)

        handler_block = ""
        if svc_names:
            handler_block = "\n      handlers:\n"
            for svc in svc_names:
                handler_block += textwrap.dedent(f"""\
                          - name: "Restart {svc}"
                            service:
                              name: "{svc}"
                              state: restarted
                """)

        return header + "\n".join(task_blocks) + handler_block

    @staticmethod
    def _assemble_index(
        fixes: list[dict[str, Any]],
        engagement: str,
        target: str,
        ts: datetime.datetime,
    ) -> str:
        """Assemble a human-readable ``fix_index.txt`` summary table."""
        lines = [
            "RTAI Proposed Fixes — Index",
            "=" * 70,
            f"Engagement : {engagement}",
            f"Target     : {target}",
            f"Generated  : {ts.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Total fixes: {len(fixes)}",
            "",
            f"{'ID':<10} {'SEV':<10} {'PORT':<7} {'SERVICE':<28} {'CVE':<20}",
            "-" * 75,
        ]
        for fix in fixes:
            lines.append(
                f"{fix.get('fix_id','?'):<10} "
                f"{fix.get('severity','?'):<10} "
                f"{str(fix.get('port','?')):<7} "
                f"{fix.get('service','?')[:27]:<28} "
                f"{fix.get('cve_id','N/A'):<20}"
            )
        lines += [
            "",
            "Files",
            "-----",
            "  Proposed_Fixes.sh          — Bash script (run with DRY_RUN=1 first)",
            "  Proposed_Fixes.ansible.yml — Ansible playbook",
            "  fix_index.txt              — This file",
        ]
        return "\n".join(lines) + "\n"

    # ------------------------------------------------------------------
    # File I/O
    # ------------------------------------------------------------------

    @staticmethod
    def _save_to_disk(
        bash_src: str,
        ansible_src: str,
        index_txt: str,
        engagement: str,
        ts: datetime.datetime,
    ) -> tuple[Path, list[str]]:
        """
        Write output files under ``Config.REMEDIATION_DIR``.

        Returns ``(output_dir, write_errors)``.  Errors are collected and
        non-fatal so the pipeline continues even if the disk is full.
        """
        errors: list[str] = []
        date_str = ts.strftime("%Y-%m-%d")
        # Sanitise engagement name for filesystem use
        safe_name = "".join(
            c if c.isalnum() or c in ("-", "_") else "_"
            for c in engagement
        )
        out_dir = Config.REMEDIATION_DIR / f"{safe_name}_{date_str}"

        try:
            out_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            errors.append(f"Cannot create output directory {out_dir}: {exc}")
            return out_dir, errors

        files = {
            "Proposed_Fixes.sh": bash_src,
            "Proposed_Fixes.ansible.yml": ansible_src,
            "fix_index.txt": index_txt,
        }
        for filename, content in files.items():
            path = out_dir / filename
            try:
                path.write_text(content, encoding="utf-8")
                if filename.endswith(".sh"):
                    path.chmod(0o750)   # executable by owner/group, not world
            except OSError as exc:
                errors.append(f"Failed to write {path}: {exc}")

        return out_dir, errors

    # ------------------------------------------------------------------
    # State partial builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_partial(
        fixes: list[dict[str, Any]],
        output_dir: Path,
        write_errors: list[str],
        target: str,
    ) -> dict[str, Any]:
        counts = {
            sev: sum(1 for f in fixes
                     if f.get("severity", "").lower() == sev)
            for sev in ("critical", "high", "medium", "low")
        }
        disruptive_count = sum(1 for f in fixes if f.get("potentially_disruptive"))

        result: dict[str, Any] = {
            "target": target,
            "total_fixes": len(fixes),
            "critical_count": counts["critical"],
            "high_count": counts["high"],
            "medium_count": counts["medium"],
            "low_count": counts["low"],
            "disruptive_count": disruptive_count,
            "output_dir": str(output_dir),
            "files": {
                "bash":    str(output_dir / "Proposed_Fixes.sh"),
                "ansible": str(output_dir / "Proposed_Fixes.ansible.yml"),
                "index":   str(output_dir / "fix_index.txt"),
            },
            "write_errors": write_errors,
            "fixes": fixes,
        }

        # Build one remediation record per fix (RTAIState.remediations convention)
        remediations = [
            {
                "phase": "fixer",
                "fix_id": f.get("fix_id", ""),
                "title": f.get("title", ""),
                "severity": f.get("severity", ""),
                "ip": f.get("ip", target),
                "port": f.get("port", 0),
                "service": f.get("service", ""),
                "cve_id": f.get("cve_id", "N/A"),
                "verification_cmd": f.get("verification_cmd", ""),
                "notes": f.get("notes", ""),
                "potentially_disruptive": f.get("potentially_disruptive", False),
                "disruption_reasons": f.get("disruption_reasons", []),
            }
            for f in fixes
        ]

        return {
            "tool_outputs": {"fixer": result},
            "remediations": remediations,
            "findings": [
                {
                    "phase": "fixer",
                    "target": target,
                    "total_fixes": len(fixes),
                    "critical_count": counts["critical"],
                    "high_count": counts["high"],
                    "disruptive_count": disruptive_count,
                    "output_dir": str(output_dir),
                    "write_errors": write_errors,
                }
            ],
            "current_step": "fixer_complete",
            "finished": True,
        }


# =============================================================================
# Backward-compatibility shim — was agents/remediation_agent.py
# RemediationAgent has been consolidated into this module.
# =============================================================================

_REMEDIATION_RISK_RANK: dict[str, int] = {
    "critical": 0, "high": 1, "medium": 2, "low": 3
}


class RemediationAgent(BaseAgent):
    """
    Backward-compatibility alias for the legacy RemediationAgent.

    Produces per-vector structured remediation entries (steps, code_snippet,
    verification) compatible with the legacy LangGraph orchestrator pipeline
    (core/orchestrator.py).  For new engagements prefer ``FixerAgent``.
    """

    role = "Remediation Engineer"
    goal = (
        "For every confirmed attack vector, produce step-by-step remediation "
        "instructions including shell commands, configuration changes, and "
        "code patches so a system administrator can immediately act on the findings."
    )

    def run(self, state: RTAIState) -> dict[str, Any]:
        """
        Generate structured remediations for every exploit vector in state.

        Args:
            state: Shared engagement state; reads ``findings[phase=exploit_analysis]``
                   and ``findings[phase=osint]``.

        Returns:
            Partial state dict with ``remediations`` list, a ``findings`` entry
            with ``phase="remediation"``, and ``current_step="remediation_complete"``.
        """
        exploit_finding = next(
            (f for f in state.findings if f.get("phase") == "exploit_analysis"), {}
        )
        osint_finding = next(
            (f for f in state.findings if f.get("phase") == "osint"), {}
        )

        attack_vectors = exploit_finding.get("attack_vectors", "")
        top_3_risks    = osint_finding.get("top_3_risks", [])

        if not attack_vectors:
            return {
                "remediations": [],
                "findings": [{
                    "phase": "remediation",
                    "target": state.target,
                    "remediations": [],
                    "summary": "No attack vectors to remediate.",
                }],
                "current_step": "remediation_complete",
            }

        remediations = self._generate_remediations(
            state.target, attack_vectors, top_3_risks
        )
        remediations.sort(
            key=lambda r: _REMEDIATION_RISK_RANK.get(
                r.get("risk_level", "").lower(), 99
            )
        )

        return {
            "remediations": remediations,
            "findings": [{
                "phase": "remediation",
                "target": state.target,
                "remediations": remediations,
            }],
            "current_step": "remediation_complete",
        }

    def _generate_remediations(
        self,
        target: str,
        attack_vectors: str,
        top_3_risks: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Call the LLM to produce a structured JSON remediation array.

        Args:
            target: Target IP/hostname.
            attack_vectors: Free-text list of attack vectors from ExploitAgent.
            top_3_risks: Structured OSINT risk list from OsintAgent.

        Returns:
            List of remediation dicts; falls back to a single unstructured entry
            if the LLM response cannot be parsed as JSON.
        """
        from langchain_core.messages import HumanMessage, SystemMessage

        messages = [
            SystemMessage(content=self._system_prompt()),
            HumanMessage(
                content=(
                    f"Target: {target}\n\n"
                    f"Attack vectors identified by ExploitAgent:\n{attack_vectors}\n\n"
                    f"OSINT top-3 risks (CVEs / PoCs / default creds):\n"
                    f"{json.dumps(top_3_risks, indent=2)}\n\n"
                    "For EACH numbered attack vector above, produce a remediation entry.\n"
                    "Return ONLY a valid JSON array (no markdown fences) where every "
                    "element matches this schema exactly:\n"
                    "{\n"
                    '  "id": <integer>,\n'
                    '  "title": "<short imperative title>",\n'
                    '  "risk_level": "<Critical | High | Medium | Low>",\n'
                    '  "service": "<affected service and version>",\n'
                    '  "cve": "<CVE-XXXX-XXXX or N/A>",\n'
                    '  "steps": ["<step 1>", ...],\n'
                    '  "code_snippet": "<shell commands or null>",\n'
                    '  "verification": "<single runnable check>"\n'
                    "}\n\n"
                    "Rules:\n"
                    "- steps must be specific shell commands, not vague advice\n"
                    "- code_snippet should be copy-paste ready bash/yaml/config\n"
                    "- verification must be a concrete, runnable check\n"
                    "- risk_level must match the level assigned by ExploitAgent"
                )
            ),
        ]
        response = self.llm.invoke(messages)
        try:
            return json.loads(response.content)
        except (json.JSONDecodeError, ValueError):
            return [{
                "id": 0,
                "title": "Remediation guidance (unstructured)",
                "risk_level": "Unknown",
                "service": "N/A",
                "cve": "N/A",
                "steps": [response.content],
                "code_snippet": None,
                "verification": "N/A",
            }]

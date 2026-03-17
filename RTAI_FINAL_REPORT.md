# RTAI — Comprehensive Technical Upgrade Report
**Project:** RTAI — Autonomous Multi-Agent Red Team Swarm
**Report Date:** 2026-03-09
**Branch:** maintenance/2026-audit
**Author:** Claude Code (Anthropic) × RTAI Engineering

---

## Table of Contents
1. [Core Architecture Shift](#1-core-architecture-shift)
2. [Agent Breakdown](#2-agent-breakdown)
3. [The Safety Layer](#3-the-safety-layer)
4. [Network Capabilities](#4-network-capabilities)
5. [External Integrations](#5-external-integrations)
6. [DevOps & Security](#6-devops--security)
7. [Dependency Map](#7-dependency-map)
8. [Known Issues Fixed This Session](#8-known-issues-fixed-this-session)

---

## 1. Core Architecture Shift

### From Single-Flow to Multi-Agent Swarm

The original RTAI architecture used a single LangGraph `StateGraph` with a hardcoded
linear node sequence managed by `core/orchestrator.py`. While functional, this design
tightly coupled all reconnaissance and reporting logic into one execution context,
making it difficult to extend, test, or parallelize individual stages.

The new architecture replaces this with a **SwarmController pipeline** — a lightweight
orchestrator that executes a list of independent `BaseAgent` subclasses in sequence,
each reading from and writing to a shared `RTAIState` object.

### Shared State: RTAIState

`core/state.py` defines a Pydantic `BaseModel` that flows through the entire pipeline:

```
RTAIState
├── target              : str        — scanned IP / CIDR
├── engagement_name     : str        — human label for this run
├── findings            : list[dict] — accumulates across all agents (operator.add)
├── tool_outputs        : dict       — keyed by agent name (scout, analyst, fixer…)
├── osint_results       : list[dict] — OSINT hits (operator.add)
├── remediations        : list[dict] — proposed remediations (operator.add)
├── action_log          : list[dict] — chronological event log (operator.add)
├── current_step        : str        — last completed stage (scalar, overwritten)
├── finished            : bool       — set True by FixerAgent on completion
├── awaiting_approval   : bool       — approval gate flag
├── approval_granted    : bool       — human-in-loop confirmation
└── report              : str        — final markdown output
```

List fields use `operator.add` semantics — each agent **appends** new entries rather
than replacing them, creating a cumulative engagement history in one object.

### Pipeline Execution

```
SwarmController.PIPELINE = [
    ScoutAgent,
    AnalystAgent,
    StrategistAgent,
    FixerAgent,
    ReportAgent,      ← added this session (fixes sidebar not updating)
]
```

Each agent follows the `BaseAgent.execute()` pattern:
1. Logs `start` event to `action_log`
2. Calls `self.run(state)` — returns a partial dict
3. Merges partial into state via `_merge_partial()`
4. Logs `complete` event

`_merge_partial()` rules:
- **Lists** → appended
- **Dicts** → shallow-merged (new keys win on collision)
- **Scalars** → overwritten

This design means any agent can be added, removed, or reordered by modifying
`SwarmController.PIPELINE` without touching other agent code.

---

## 2. Agent Breakdown

### 2.1 ScoutAgent

**Role:** Network reconnaissance — enumerate live hosts, open ports, services, OS.

**Pipeline position:** 1st

**Core logic:**
- Classifies target as single IP or CIDR range (presence of `/`)
- For CIDR: runs a two-phase discovery before the full service scan (see §4)
- For single IP: calls scapy ICMP ping (root) or skips discovery (-Pn)
- Runs nmap service scan against confirmed live hosts only
- Maps 37 well-known ports to `risk_hint` strings
- Calls LLM for narrative attack-surface summary

**Nmap scan arguments:**

| Privilege | Arguments |
|-----------|-----------|
| Root      | `-sS -sV -O -Pn --open -T2` (SYN stealth) |
| No root   | `-sT -sV -Pn --open -T3` (TCP connect) |

**Output stored in:** `state.tool_outputs["scout"]`

```json
{
  "target": "192.168.56.143",
  "scan_metadata": { "scan_mode": "tcp_connect", "run_as_root": false, ... },
  "hosts": [{
    "ip": "192.168.56.143",
    "state": "up",
    "discovery_method": "nmap",
    "os_guesses": [{"name": "Debian Linux", "accuracy": "95"}],
    "open_ports": [{
      "port": 22, "protocol": "tcp", "service": "ssh",
      "product": "OpenSSH", "version": "10.2p1",
      "risk_hint": "SSH – prime brute-force target if credentials are weak"
    }]
  }],
  "attack_surface": {
    "total_hosts_up": 1, "total_open_ports": 3,
    "high_risk_ports": [22, 80], "llm_summary": "..."
  }
}
```

---

### 2.2 AnalystAgent

**Role:** Cross-reference discovered services against CVE database; compute Dynamic Risk Scores.

**Pipeline position:** 2nd

**Core logic:**

*CveDatabase* — embedded database of 40+ real CVEs covering SSH, Apache, nginx,
vsftpd, MySQL, PostgreSQL, Samba, Redis, OpenSSL, Tomcat, VNC, Elasticsearch,
MongoDB, RDP, and Telnet. Version matching handles OpenSSH `p` suffixes and
single-letter build tags. Empty/unknown versions default to **vulnerable** (safe-fail).

*Dynamic Risk Score formula:*
```
score = min(10.0,
    cvss_base × reachability_multiplier
    + exploit_bonus        (0.5 if exploit available)
    + auth_bypass_bonus    (1.0 if exploit type = AuthBypass)
)

reachability multipliers:
  80/443 (web)          → 1.30
  22/3389/5900 (remote) → 1.20–1.25
  databases             → 1.10–1.15
  other                 → 1.00–1.05
```

Scores > 8.0 → Critical. 6.0–7.9 → High. 4.0–5.9 → Medium. < 4.0 → Low.

Top-10 entry points are sent to the LLM for tactical enrichment (notes on attack
difficulty, pivoting potential, and detection likelihood).

**Output stored in:** `state.tool_outputs["analyst"]` — list of ranked `entry_points`
sorted descending by `dynamic_risk_score`.

---

### 2.3 StrategistAgent

**Role:** Turn raw entry points into an actionable, multi-step attack plan.

**Pipeline position:** 3rd

**Three-step LLM reasoning chain:**

**Step 1 — Triage**
Receives top-12 entry points. LLM scores each on exploit reliability, severity,
service exposure, and stealth preference. Returns JSON array of top-3 footholds
with justification, technique, tools, and stealth rating.
Fallback: top-3 by Dynamic Risk Score if JSON parse fails.

**Step 2 — Path Planning**
Receives footholds + full attack surface. LLM designs a multi-hop path using
only services discovered by ScoutAgent. Each step specifies:
`type` (initial_access / privilege_escalation / lateral_movement / persistence /
objective), `ip:port`, `technique`, `cve_id`, `tools`, `success_indicator`, `fallback`.

**Step 3 — Battle Plan Narration**
LLM synthesises steps 1–2 into a structured Markdown document with:
- Per-phase headers with target:port, technique, CVE
- Specific commands and expected output per phase
- OPSEC considerations
- `### Detection & IOC Notes` — observable indicators for blue team
- `### Abort Criteria` — scope breach / unexpected data / SOC detection conditions

**Output stored in:**
- `state.tool_outputs["attack_path"]` — path_nodes list
- `state.tool_outputs["strategy"]` — battle plan text
- `state.findings[phase=strategist]` — overall_risk, total_steps, path_summary

---

### 2.4 FixerAgent

**Role:** Auto-generate hardening scripts for every identified vulnerability.

**Pipeline position:** 4th

**Core logic:**
- Reads Analyst's `entry_points` + Strategist's `battle_plan`
- Batches entry points (5 at a time) to respect LLM token limits
- LLM produces per-fix JSON with: `bash_snippet`, `iptables_rules`, `ansible_task`,
  `verification_cmd`, `title`, `severity`, `cve_id`, `notes`
- Falls back to template-based fixes if LLM response is malformed

**Bash generation rules enforced via prompt:**
- Must use `if command -v apt-get … elif command -v yum … elif command -v dnf`
- `iptables-save` called after firewall changes
- No hardcoded package manager assumptions

**Three output files written to `remediation/<engagement>_<date>/`:**

| File | Format | Purpose |
|------|--------|---------|
| `Proposed_Fixes.sh` | Bash | Per-fix functions; supports `all`, `fix_NNN`, `list`, `DRY_RUN=1` |
| `Proposed_Fixes.ansible.yml` | YAML | Full playbook with tags `[severity, fix_id, cve_id]` and handlers |
| `fix_index.txt` | Plain text | Human-readable table: ID, SEV, PORT, SERVICE, CVE |

---

## 3. The Safety Layer

Two safety mechanisms prevent accidental disruption of production services.

### 3.1 ServiceImpactAnalyzer

Detects when a proposed fix would restart a **high-traffic service** (DNS on port 53,
HTTP/HTTPS on ports 80, 443, 8080, 8443). For these services, the generated bash
snippet wraps any `systemctl restart` command in a maintenance-window guard:

```bash
if [ "${MAINTENANCE_OVERRIDE:-0}" = "1" ]; then
    systemctl restart nginx
elif [ "$(date +%H)" -ge 02 ] && [ "$(date +%H)" -lt 05 ]; then
    systemctl restart nginx
else
    echo "WARNING: Restart deferred — run between 02:00–05:00 \
or set MAINTENANCE_OVERRIDE=1"
fi
```

This ensures that patching a web server during business hours does not silently
bounce live traffic. The operator can override with `MAINTENANCE_OVERRIDE=1` when
a manual maintenance window is scheduled.

### 3.2 The Approval Bridge (Human-in-the-Loop Gate)

After all pipeline agents complete, `SwarmController._request_approval()` sets:
- `state.awaiting_approval = True`
- `state.current_step = "AWAITING_APPROVAL"`

A Telegram notification is sent (if configured) listing the total fix count broken
down by severity, and specifically calling out any **disruptive fixes** (those that
match reboot, shutdown, critical service stop, or blanket firewall flush patterns).

In the Streamlit dashboard's **Remediation** tab, the *Apply Fixes* button remains
**disabled** until the operator clicks *Approve*, which sets `approval_granted = True`.
No remediation script can be executed without this explicit confirmation step.

The three-tier safety filter in FixerAgent flags commands matching:

| Category | Detected patterns |
|----------|-------------------|
| Reboot/shutdown | `reboot`, `shutdown`, `halt`, `poweroff`, `init 6` |
| Critical service stop | `sshd`, `networking`, `firewalld`, `wpa_supplicant`, `systemd-resolved` |
| Firewall disruption | `iptables -P DROP`, `-F`, `--flush` (blanket policy changes) |

Flagged fixes receive `potentially_disruptive: true` and a `disruption_reasons` list,
which surface in both the Telegram alert and the Dashboard remediation view.

---

## 4. Network Capabilities

### 4.1 Subnet Discovery Logic

When the target contains `/` (e.g. `192.168.56.0/24`), ScoutAgent enters
**subnet mode** with a two-phase discovery before running the service scan.

**Phase 2a — ARP Sweep (preferred)**
- Requires: root privileges + scapy installed
- Broadcasts ARP requests across the entire CIDR
- Only live hosts reply → nmap never touches dead addresses
- Scan time and network noise scale with live host count, not subnet size
- Result: `{ip: "arp"}` dict of confirmed-live IPs

**Phase 2b — Nmap Ping Sweep (fallback)**
- Used when scapy absent or process is not root
- Root: `-sn -PE -PS22,80,443 -T4` (SYN + ICMP probes)
- No root: `-sn -T4` (TCP connect ping only)
- Result: list of hosts with `state = "up"`

**Phase 2c — Full-subnet fallback**
- Triggered if both 2a and 2b return zero hosts
- nmap receives the original CIDR and performs its own host detection

After discovery, the service scan target is narrowed to confirmed live IPs only
(space-separated list passed to nmap), dramatically reducing scan time on large subnets.

### 4.2 SCAN_SELF Feature

Controlled by `SCAN_SELF=True` in `.env` (default: `False`).

When enabled, ScoutAgent always injects `127.0.0.1` and the machine's primary LAN IP
into the scan queue, regardless of discovery results. The LAN IP is resolved by opening
a UDP socket toward `8.8.8.8:80` — no data is sent; the OS assigns the outbound
interface IP which is read from the bound socket address.

This prevents false-clean results when the RTAI host itself is within the target scope
but does not respond to ARP or ping probes (e.g. localhost loopback filtering).

---

## 5. External Integrations

### 5.1 Telegram Bot Alerting

**Configuration** (`.env`):
```
TELEGRAM_BOT_TOKEN=<BotFather token>
TELEGRAM_CHAT_ID=<recipient user/group ID>
```

Two notification events:

**Event 1 — Post-Pipeline Approval Alert** (SwarmController)
Sent immediately after all agents complete. Contains:
- Engagement name + target
- Fix counts by severity (Critical / High / Medium / Low)
- List of disruptive fixes requiring special attention

**Event 2 — Full Engagement Report** (Dashboard `run_swarm`)
Sent when swarm completes via the Streamlit UI. Single message containing:

```
🛡 RTAI — {engagement}
🎯 Target: {ip}   🕐 {timestamp}
{risk_emoji} Overall Risk: {level}
🖥 Hosts: N   🔓 Open ports: N   ⚠ High-risk: [ports]

SCOUT — HOSTS & PORTS
🔵 {ip} ({OS})
  {port/proto}  {service} {version} — {risk hint}

ANALYST — CVE ENTRY POINTS
{emoji} {ip:port}  {svc}  Score:{DRS}  CVEs: [list]

STRATEGIST — ATTACK PATH
  1. {ip:port} — {technique} ({service})
  2. …
  Plan: {first 300 chars}

FIXER — N REMEDIATIONS
Scripts: {output_dir}
{emoji} {ip:port} {svc} — {description}
```

The message is limited to 4096 characters (Telegram API hard limit). Content is
trimmed from the end to fit. If Markdown parsing fails (unmatched backticks or
asterisks in report text), the notifier automatically retries as plain text.

If `TELEGRAM_BOT_TOKEN` or `TELEGRAM_CHAT_ID` is absent/unconfigured, both
notification events are silently skipped — they are non-fatal and never block the pipeline.

---

### 5.2 Streamlit CISO Dashboard

**Launch:** `streamlit run dashboard.py`
**Default port:** http://localhost:8501

**Four tabs:**

#### Tab 1 — CISO Overview
- Engagement selector sidebar (sorted by file modification time)
- Risk metric cards: Total Findings / Critical / High / Medium / Low
- Plotly bar chart: risk distribution across all engagements
- Plotly donut chart: selected engagement severity breakdown
- Open ports grid (color-coded: red port number / gray protocol)
- Full markdown report viewer (monospace, 640px max-height)

#### Tab 2 — Swarm Live Feed
- Chronological `action_log` stream (newest-first)
- Per-agent status cards with role icons
- Color-coded entries: blue (start), green (complete), red (error), yellow (warning)
- Pulsing red indicator for Critical/High severity events

#### Tab 3 — Network Map
Interactive `streamlit-agraph` graph populated from Scout + Analyst + Strategist output:

| Node type | Shape | Color | Size |
|-----------|-------|-------|------|
| Attacker  | Star  | Purple | 32px |
| Host (Critical) | Dot | Red | 50px |
| Host (High) | Dot | Orange | 38px |
| Host (Medium/Low) | Dot | Blue | 22–28px |
| Port node | Dot | Green | 16–24px |

Attack path edges (from Strategist path_nodes) rendered as **bold red arrows** (width=5)
tracing initial_access → privilege_escalation → lateral_movement → objective.
Normal connectivity edges are thin gray lines.

#### Tab 4 — Remediation
- `Proposed_Fixes.sh` viewer (read-only)
- **DRY RUN** button: executes with `DRY_RUN=1` — previews without applying
- **Approve + Apply** button: gated by `awaiting_approval` flag
- Per-fix selector for targeted single-fix execution

**Sidebar Run Swarm control:**
- Target IP / Range input
- Engagement Name input
- `▶ Run Swarm` button — executes full pipeline with live per-agent status
- On completion: saves state JSON, sends Telegram report, calls `st.rerun()` to refresh
  the engagement list (this session fix: `ReportAgent` added to pipeline so `.md` files
  are written and the sidebar refreshes automatically)

---

## 6. DevOps & Security

### 6.1 .gitignore Protection

The following paths are excluded from version control to prevent secret or sensitive
engagement data from being committed:

```
.env                  # API keys, bot tokens, credentials
reports/              # Real engagement data (hostnames, CVEs, vulnerabilities)
logs/                 # Execution logs
remediation/          # Generated hardening scripts
.venv/                # Python virtual environment
__pycache__/          # Compiled bytecode
*.py[cod]
.claude/              # Claude Code local settings
*.pptx                # Generated executive report files
```

### 6.2 .env Protection Logic

`core/config.py` loads `.env` via `python-dotenv` at import time.
`Config.validate()` raises `EnvironmentError` immediately if any mandatory variable
is missing — `OPENAI_API_KEY`, `TAVILY_API_KEY`, `TARGET_SCOPE` — preventing silent
half-configured runs.

Optional variables (`TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`) default to empty string.
All consumers check for empty/placeholder values and skip gracefully rather than failing.

The `SCAN_SELF` variable uses an explicit allowlist (`"1"`, `"true"`, `"yes"`) to
prevent accidental activation from unexpected env values.

### 6.3 Circular Import Fix

`core/__init__.py` intentionally does **not** export `Orchestrator`. It must be
imported directly:
```python
from core.orchestrator import Orchestrator   # correct
from core import Orchestrator                # wrong — circular import
```

---

## 7. Dependency Map

| Package | Purpose | Required |
|---------|---------|----------|
| `langchain` | Agent/chain framework | Yes |
| `langchain-community` | Tool integrations | Yes |
| `langchain-openai` | ChatOpenAI LLM binding | Yes |
| `langgraph` | StateGraph (legacy orchestrator) | Yes |
| `python-nmap` | nmap Python bindings | Yes |
| `python-dotenv` | `.env` loader | Yes |
| `pydantic` | RTAIState model | Yes |
| `colorama` | CLI colour output | Yes |
| `streamlit` | CISO Dashboard UI | Dashboard only |
| `streamlit-agraph` | Network Map graph | Dashboard only |
| `plotly` | Risk charts | Dashboard only |
| `scapy` | ARP/ICMP host discovery | Optional |
| `tavily-python` | OSINT web search | Yes (OSINT agent) |

---

## 8. Known Issues Fixed This Session

| Issue | Root Cause | Fix Applied |
|-------|-----------|-------------|
| `No module named 'streamlit_agraph'` | Package not installed | `pip install streamlit-agraph` |
| `No module named 'langchain_openai'` | Package not installed | `pip install langchain-openai` |
| `No module named 'tavily'` | Package not installed | `pip install tavily-python` |
| `No module named 'nmap'` (inside Streamlit) | `python-nmap` installed in venv but not system Python used by Streamlit | `pip install python-nmap --break-system-packages` |
| Port 22 missing from scan results | All scans returning 0 results due to nmap module not found | Resolved by above fix |
| New engagements not appearing in sidebar | `ReportAgent` was not in `SwarmController.PIPELINE` so no `.md` files were written | Added `ReportAgent` as 5th pipeline stage |
| Telegram sending multiple messages | Notifier split content into 6 separate messages | Rewrote to build one single compact message ≤ 4096 chars |
| Telegram Markdown parse error 400 | Report markdown had unmatched backticks/asterisks | Added plain-text fallback retry on HTTP 400 |
| `TELEGRAM_CHAT_ID=your_id_here` | Placeholder not replaced | Set to operator's real chat ID |

---

*Report generated by Claude Code — RTAI maintenance/2026-audit session — 2026-03-09*

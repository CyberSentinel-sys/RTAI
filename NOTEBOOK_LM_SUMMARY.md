# RTAI — Autonomous Multi-Agent Red Team System
## Technical Summary for NotebookLM

---

## 1. What Is RTAI?

RTAI (Red Team AI) is a fully autonomous, multi-agent cybersecurity assessment framework built on top of LangChain, LangGraph, and OpenAI GPT-4o. It replaces the traditional manual penetration-testing workflow — where a human operator runs tools one at a time and interprets results manually — with a coordinated swarm of specialised AI agents that reason, plan, and remediate vulnerabilities end-to-end.

The system is designed for **authorised engagements only**. Every scan, finding, and fix is scoped to a declared target range, logged with a timestamp, and gated behind a human-approval step before any remediation script can execute.

---

## 2. The Swarm Architecture

RTAI's "swarm" is a linear pipeline of four specialised agents, each inheriting from a common `BaseAgent` base class and communicating through a shared Pydantic state object (`RTAIState`).

```
Scout Agent → Analyst Agent → Strategist Agent → Fixer Agent
                                                       ↓
                                              [APPROVAL GATE]
                                                       ↓
                                            Proposed_Fixes.sh
                                            Proposed_Fixes.ansible.yml
```

### Stage 1 — Scout Agent (`agents/scout_agent.py`)
The Scout is the framework's eyes. It performs stealthy, two-phase network reconnaissance:

- **Phase A — Host Discovery**: Uses Scapy's ARP broadcast sweep (when running as root on a local subnet) to identify live hosts *before* any port scan. Only live hosts are forwarded to nmap, drastically reducing scan time and network noise.
- **Phase B — Service Scan**: Runs nmap in SYN-stealth mode (root) or TCP-connect mode (unprivileged) against the discovered host list. Collects open ports, service versions, OS fingerprints, and maps every finding to a pre-built risk-hint dictionary covering 30+ well-known dangerous ports.
- **SCAN_SELF Mode**: When `SCAN_SELF=True` in `.env`, the Scout automatically force-injects `127.0.0.1` and the machine's primary LAN IP into the scan queue using a UDP dummy-connect technique, regardless of whether they respond to discovery probes.
- **LLM Attack-Surface Summary**: The full structured JSON result is passed to GPT-4o, which returns a risk-rated narrative covering top attack vectors and anomalies.

### Stage 2 — Analyst Agent (`agents/analyst_agent.py`)
The Analyst cross-references every discovered open port and service against a local CVE database (`CveDatabase` class, subclassable for custom feeds). It computes a **Dynamic Risk Score** (0–10) per entry point, factoring in CVSS scores, exploit availability, and service exposure level. Output is a ranked list of `entry_points` stored in `state.tool_outputs["analyst"]`.

### Stage 3 — Strategist Agent (`agents/strategist_agent.py`)
The Strategist is the framework's "brain." It consumes the Analyst's ranked entry points and reasons over them using the LLM to produce an ordered **Battle Plan**: a step-by-step attack strategy sorted from lowest-noise/lowest-risk-of-detection to highest-impact. Each step includes an objective, technique, expected outcome, and fallback option.

### Stage 4 — Fixer Agent (`agents/fixer_agent.py`)
The Fixer converts every entry point into three forms of executable remediation:

1. **Bash script** (`Proposed_Fixes.sh`) — one function per fix, with package-manager auto-detection (`apt` / `yum` / `dnf`), IPTables firewall rules, and a dispatcher supporting `all`, `fix_001`, `list`, and `DRY_RUN=1` modes.
2. **Ansible playbook** (`Proposed_Fixes.ansible.yml`) — production-grade, tagged by severity and CVE.
3. **Fix index** (`fix_index.txt`) — human-readable summary table.

A **Safety Filter** inspects every generated script for reboot/shutdown commands, restarts of critical infrastructure services (sshd, firewalld, networking, etc.), and firewall rule flushes, flagging them as "potentially disruptive" before presenting them to the operator.

---

## 3. The ServiceImpactAnalyzer

Before the Fixer finalises any bash fix, it runs every script through the **ServiceImpactAnalyzer**. This component checks whether the affected port is classified as "High Traffic":

| Port | Service | Reason |
|------|---------|--------|
| 53   | DNS     | Resolver restart breaks name resolution fleet-wide |
| 80   | HTTP    | Production web traffic |
| 443  | HTTPS   | TLS production web traffic |
| 8080 | HTTP alt| Common app-server traffic |
| 8443 | HTTPS alt| Common app-server TLS traffic |

When a service-restart command targets a high-traffic port, the analyzer wraps it in a **maintenance-window conditional**:

```bash
if [ "${MAINTENANCE_OVERRIDE:-0}" = "1" ]; then
    systemctl restart apache2
elif [ "$(date +%H)" -ge 02 ] && [ "$(date +%H)" -lt 05 ]; then
    systemctl restart apache2
else
    echo "WARNING: Restart of 'apache2' deferred. Run during 02:00–05:00
          or set MAINTENANCE_OVERRIDE=1."
fi
```

This ensures that a security fix pushed during peak hours does not accidentally take down a production web server. The operator can override with `MAINTENANCE_OVERRIDE=1` when needed.

---

## 4. Human-in-the-Loop: The Approval Gate

RTAI enforces a strict **Human-in-the-Loop** policy. No remediation script is ever executed automatically.

### The Flow
1. FixerAgent writes `Proposed_Fixes.sh` and `Proposed_Fixes.ansible.yml` to `remediation/<engagement>_<date>/`.
2. `SwarmController._request_approval()` sets `state.awaiting_approval = True` and `state.current_step = "AWAITING_APPROVAL"`.
3. The **Telegram Notifier** sends an alert to the operator's mobile:
   > ⚠️ Vulnerabilities Found on {target}. Review the Battle Plan in the Dashboard and click APPROVE to execute fixes.
4. The Streamlit CISO Dashboard displays the findings and an **APPROVE** button. The Apply Fixes button is disabled until approval is granted.
5. When the operator clicks Approve, the Dashboard calls `ApprovalBridge.approve()`, which writes a `.approved` signal file to the remediation directory.
6. Any code attempting to execute `Proposed_Fixes.sh` must first call `ApprovalBridge.execute_if_approved()` (or `wait_for_approval()`). Without the signal file, execution is blocked with a descriptive error.

### ApprovalBridge (`core/approval_bridge.py`)
A lightweight, file-based gate with no external dependencies:
- `approve(engagement, output_dir)` — writes signal, unblocks waiters
- `is_approved(engagement, output_dir)` — non-blocking check
- `wait_for_approval(engagement, output_dir, timeout)` — polling block
- `execute_if_approved(...)` — executes script or returns `(False, "blocked")
- `revoke(...)` — removes signal to re-gate (useful for rollback scenarios)

---

## 5. Telegram Integration

The Telegram bot serves as the real-time operations channel between RTAI and the operator's mobile device.

**Setup**: Create a bot via @BotFather, retrieve the chat ID from @userinfobot, and set both in `.env`:
```
TELEGRAM_BOT_TOKEN=<token>
TELEGRAM_CHAT_ID=<chat_id>
```

**Trigger**: The notification fires automatically after the Fixer Agent completes, before any fix is allowed to run. It is non-blocking — if Telegram is unreachable, the approval gate still activates.

---

## 6. The CISO Dashboard

Built with Streamlit + Plotly, the Dashboard provides:
- **Tab 1 — Network Map**: Interactive force-directed graph of discovered hosts and services
- **Tab 2 — Attack Surface**: Severity-bucketed bar charts and heat maps
- **Tab 3 — Battle Plan**: The Strategist's step-by-step attack strategy
- **Tab 4 — Remediation Center**: Fix list with disruptive-fix warnings, the APPROVE gate, and one-click script execution
- **Tab 5 — Executive Report**: Auto-generated Markdown report exportable to PowerPoint (via `generate_pptx.py`)

---

## 7. Configuration & Security Model

| Variable | Purpose |
|----------|---------|
| `OPENAI_API_KEY` | GPT-4o LLM backend |
| `TAVILY_API_KEY` | OSINT web-search tool |
| `TELEGRAM_BOT_TOKEN` | Bot authentication |
| `TELEGRAM_CHAT_ID` | Operator notification target |
| `TARGET_SCOPE` | Authorised CIDR range or IP |
| `SCAN_SELF` | Include localhost + LAN IP in scan |
| `ENGAGEMENT_NAME` | Label for reports and remediation folders |

All secrets live exclusively in `.env`, which is git-ignored. No credential ever touches the codebase or version history.

---

## 8. Key Design Principles

1. **Zero-Harm by Default**: No command executes without operator approval. High-traffic service restarts are time-gated.
2. **Least Privilege Awareness**: The Scout automatically degrades from SYN-stealth to TCP-connect when not running as root, and from ARP sweep to nmap ping sweep when Scapy is unavailable.
3. **Modular Pipeline**: The `PIPELINE` list in `SwarmController` is a plain Python list. Adding, removing, or reordering agents requires one line of code.
4. **Observable State**: Every agent action is appended to `state.action_log` with a timestamp. The full engagement trace is available at any point.
5. **Graceful Degradation**: Missing optional dependencies (Scapy, Telegram) produce informational warnings, not crashes. The pipeline always completes.

---

## 9. Technology Stack

| Layer | Technology |
|-------|-----------|
| LLM Backbone | OpenAI GPT-4o via LangChain |
| Agent Orchestration | LangGraph `StateGraph` |
| Network Scanning | python-nmap, Scapy |
| State Management | Pydantic v2 `BaseModel` |
| Dashboard | Streamlit + Plotly |
| Notifications | Telegram Bot API (stdlib `urllib`) |
| Remediation Scripting | Bash + Ansible YAML |
| Reporting | Markdown → PowerPoint (python-pptx) |

---

*Generated for NotebookLM — RTAI Project, 2026*

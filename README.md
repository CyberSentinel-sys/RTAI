# RTAI — AI-Driven Red Team Framework

An autonomous penetration-testing framework powered by [LangGraph](https://github.com/langchain-ai/langgraph) and OpenAI. RTAI orchestrates five specialised AI agents through a strictly linear pipeline — from raw network reconnaissance to a publication-ready Markdown report with concrete, copy-paste remediation steps.

> **Legal notice:** This tool is intended for use against systems you own or have explicit written authorisation to test. Unauthorised use is illegal.

---

## Pipeline

```
START
  │
  ▼
┌──────────────────┐
│   ReconAgent     │  Nmap scan (service/version/OS detection)
│                  │  LLM interprets open ports and attack surface
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│   OsintAgent     │  Tavily search: "[Service] [Version] known vulnerabilities exploits"
│                  │  LLM extracts top 3 high-risk findings (CVEs, PoCs, default creds)
│                  │  → stored as structured top_3_risks in state.findings
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│   ExploitAgent   │  Ranks attack vectors by likelihood & impact
│                  │  risk_level derived from OSINT CVSS scores (not inferred)
│                  │  CVE identifiers cited directly from OSINT findings
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│RemediationAgent  │  One structured remediation per attack vector
│                  │  Outputs: steps[], copy-paste code_snippet, verification command
│                  │  Sorted Critical → High → Medium → Low
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│   ReportAgent    │  Structured Markdown report
│                  │  Tables/findings built from state data (deterministic)
│                  │  Executive Summary & Conclusion written by LLM
└────────┬─────────┘
         │
        END  →  reports/<engagement>_<date>_report.md
```

---

## Report Output

| Section | Built by |
|---|---|
| Header — engagement, target, date, classification | Python / state data |
| Executive Summary | LLM narrative |
| Scope & Methodology | Python / state data |
| Reconnaissance — OS detection + open ports table | Python / Nmap results |
| OSINT Intelligence — top-3 CVE/PoC/DefaultCreds table + analyst summary | Python / OSINT findings |
| Exploitation Analysis — attack vectors with `risk_level` | Python / exploit findings |
| Remediation Plan — summary table + per-finding steps, code block, verification | Python / remediation findings |
| Conclusion | LLM narrative |

---

## Project Structure

```
RTAI/
├── agents/
│   ├── base_agent.py          # Abstract base; wraps ChatOpenAI
│   ├── recon_agent.py         # Nmap scan + LLM attack-surface analysis
│   ├── osint_agent.py         # Tavily search + top-3 high-risk synthesis
│   ├── exploit_agent.py       # Attack vector ranking (OSINT-grounded)
│   ├── remediation_agent.py   # Per-vector steps, code snippets, verification
│   └── report_agent.py        # Structured Markdown report generation
├── core/
│   ├── config.py              # dotenv loader + startup validation
│   ├── state.py               # Pydantic RTAIState (shared across all nodes)
│   └── orchestrator.py        # LangGraph StateGraph (5-node linear pipeline)
├── tools/
│   ├── tool_base.py           # Abstract BaseTool interface
│   ├── tool_registry.py       # Singleton tool registry
│   └── nmap_wrapper.py        # python-nmap → structured dict output
├── logs/
├── reports/                   # Auto-generated engagement reports
├── main.py                    # CLI entry point
├── requirements.txt
└── .env.example
```

---

## Requirements

- Python 3.10+
- `nmap` binary on `PATH` (`sudo apt install nmap`)
- [OpenAI API key](https://platform.openai.com/api-keys)
- [Tavily API key](https://app.tavily.com) (free tier available)

---

## Setup

### 1. Clone the repository

```bash
git clone git@github.com:CyberSentinel-sys/RTAI.git
cd RTAI
```

### 2. Create and activate a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure the environment

```bash
cp .env.example .env
```

Edit `.env` with your values:

| Variable | Description | Default |
|---|---|---|
| `OPENAI_API_KEY` | OpenAI API key | — |
| `TAVILY_API_KEY` | Tavily search API key | — |
| `LLM_MODEL` | Model to use | `gpt-4o` |
| `LLM_TEMPERATURE` | Sampling temperature | `0.2` |
| `TARGET_SCOPE` | Authorised target — IP, hostname, or CIDR | — |
| `ENGAGEMENT_NAME` | Label used in the report filename | `RTAI_Engagement` |

---

## Usage

```bash
# Nmap OS detection requires root
sudo .venv/bin/python main.py --target <TARGET> --engagement "<NAME>"
```

### Examples

```bash
# Single host
sudo .venv/bin/python main.py --target 192.168.1.10 --engagement "Lab_Q1"

# CIDR range
sudo .venv/bin/python main.py --target 10.0.0.0/24 --engagement "Internal_Assessment"
```

The report is saved to `reports/<engagement>_<date>_report.md` and printed to stdout.

---

## Shared State

All agents communicate through `RTAIState` (a Pydantic model). Key fields:

| Field | Type | Written by | Read by |
|---|---|---|---|
| `tool_outputs["nmap"]` | `dict` | ReconAgent | OsintAgent, ExploitAgent |
| `findings` | `list[dict]` (append) | All agents | All agents, ReportAgent |
| `osint_results` | `list[dict]` (append) | OsintAgent | ExploitAgent, ReportAgent |
| `remediations` | `list[dict]` (append) | RemediationAgent | ReportAgent |
| `report` | `str` | ReportAgent | `main.py` |

---

## Adding New Tools

1. Create `tools/my_tool.py` subclassing `BaseTool`:

```python
from tools.tool_base import BaseTool

class MyTool(BaseTool):
    name = "my_tool"
    description = "Does something useful."

    def run(self, **kwargs):
        return {"result": ...}
```

2. Register it in `tools/tool_registry.py` inside `ToolRegistry.default()`:

```python
from tools.my_tool import MyTool
cls._instance.register(MyTool())
```

---

## License

For authorised security testing and research use only.

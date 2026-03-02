# RTAI — AI-Driven Red Team Framework

An autonomous penetration-testing framework powered by [LangGraph](https://github.com/langchain-ai/langgraph) and OpenAI. RTAI orchestrates specialised AI agents through a structured engagement pipeline: reconnaissance → exploitation analysis → report generation.

> **Legal notice:** This tool is intended for use against systems you own or have explicit written authorisation to test. Unauthorised use is illegal.

---

## Architecture

```
main.py
  └── Orchestrator (LangGraph StateGraph)
        ├── ReconAgent      → runs Nmap, LLM interprets attack surface
        ├── ExploitAgent    → ranks attack vectors by risk (analysis only)
        └── ReportAgent     → generates a structured Markdown report
```

```
RTAI/
├── agents/          # LLM agent logic
├── core/            # Orchestrator, shared state, config
├── tools/           # Security tool wrappers (Nmap, …)
├── logs/            # Runtime logs
├── reports/         # Auto-generated engagement reports
├── main.py          # CLI entry point
└── requirements.txt
```

---

## Requirements

- Python 3.10+
- `nmap` binary installed and on `PATH`
- An [OpenAI API key](https://platform.openai.com/api-keys)

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

Copy the template and fill in your values:

```bash
cp .env.example .env   # or edit .env directly
```

| Variable | Description |
|---|---|
| `OPENAI_API_KEY` | Your OpenAI API key |
| `LLM_MODEL` | Model to use (default: `gpt-4o`) |
| `LLM_TEMPERATURE` | Sampling temperature (default: `0.2`) |
| `TARGET_SCOPE` | Authorised target — IP, hostname, or CIDR |
| `ENGAGEMENT_NAME` | Label used in report filename |

---

## Usage

```bash
# Nmap OS detection requires root
sudo .venv/bin/python main.py --target <TARGET> --engagement <NAME>
```

### Examples

```bash
# Single host
sudo .venv/bin/python main.py --target 192.168.1.10 --engagement "Lab_Q1"

# CIDR range
sudo .venv/bin/python main.py --target 10.0.0.0/24 --engagement "Internal_Assessment"
```

The final report is saved to `reports/<ENGAGEMENT_NAME>_report.md` and printed to stdout.

---

## Adding New Tools

1. Create `tools/my_tool.py` subclassing `BaseTool`:

```python
from tools.tool_base import BaseTool

class MyTool(BaseTool):
    name = "my_tool"
    description = "Does something useful."

    def run(self, **kwargs):
        ...
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

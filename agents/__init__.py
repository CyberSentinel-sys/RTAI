from .base_agent import BaseAgent
from .osint_agent import OsintAgent
from .exploit_agent import ExploitAgent
from .report_agent import ReportAgent
from .scout_agent import ScoutAgent, ReconAgent          # ReconAgent shim lives in scout_agent
from .analyst_agent import AnalystAgent, CveDatabase
from .fixer_agent import FixerAgent, RemediationAgent   # RemediationAgent shim lives in fixer_agent
from .strategist_agent import StrategistAgent
from .hunter_agent import HunterAgent

__all__ = [
    "BaseAgent",
    "ReconAgent",       # backward-compat shim (was recon_agent.py)
    "OsintAgent",
    "ExploitAgent",
    "RemediationAgent", # backward-compat shim (was remediation_agent.py)
    "ReportAgent",
    "ScoutAgent",
    "AnalystAgent",
    "CveDatabase",
    "FixerAgent",
    "StrategistAgent",
    "HunterAgent",
]

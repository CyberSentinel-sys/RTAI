"""
core/config.py
Loads and validates environment-based configuration via python-dotenv.
"""
import os
from pathlib import Path
from dotenv import load_dotenv


_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(_ROOT / ".env")


class Config:
    # LLM
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    LLM_MODEL: str = os.getenv("LLM_MODEL", "gpt-4o")
    LLM_TEMPERATURE: float = float(os.getenv("LLM_TEMPERATURE", "0.2"))

    # Engagement
    TARGET_SCOPE: str = os.getenv("TARGET_SCOPE", "")
    ENGAGEMENT_NAME: str = os.getenv("ENGAGEMENT_NAME", "RTAI_Engagement")

    # Paths
    LOG_DIR: Path = _ROOT / "logs"
    REPORT_DIR: Path = _ROOT / "reports"

    @classmethod
    def validate(cls) -> None:
        if not cls.OPENAI_API_KEY:
            raise EnvironmentError("OPENAI_API_KEY is not set in .env")
        if not cls.TARGET_SCOPE:
            raise EnvironmentError("TARGET_SCOPE is not set in .env")
        cls.LOG_DIR.mkdir(exist_ok=True)
        cls.REPORT_DIR.mkdir(exist_ok=True)

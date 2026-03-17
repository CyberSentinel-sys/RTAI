"""
core/config.py
Loads and validates environment-based configuration via python-dotenv.
"""
import os
from pathlib import Path
from dotenv import load_dotenv


_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(_ROOT / ".env")

_bool = lambda key, default="false": os.getenv(key, default).strip().lower() in ("1", "true", "yes")


class Config:
    # LLM
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    LLM_MODEL: str = os.getenv("LLM_MODEL", "gpt-4o")
    LLM_TEMPERATURE: float = float(os.getenv("LLM_TEMPERATURE", "0.2"))

    # Offline / Local LLM (Ollama)
    USE_LOCAL_LLM: bool = _bool("USE_LOCAL_LLM")
    LOCAL_LLM_MODEL: str = os.getenv("LOCAL_LLM_MODEL", "llama3")
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

    # OSINT
    TAVILY_API_KEY: str = os.getenv("TAVILY_API_KEY", "")
    USE_LOCAL_OSINT: bool = _bool("USE_LOCAL_OSINT")

    # Telegram
    TELEGRAM_BOT_TOKEN: str = os.getenv("TELEGRAM_BOT_TOKEN", "")
    TELEGRAM_CHAT_ID: str = os.getenv("TELEGRAM_CHAT_ID", "")

    # Engagement
    TARGET_SCOPE: str = os.getenv("TARGET_SCOPE", "")
    ENGAGEMENT_NAME: str = os.getenv("ENGAGEMENT_NAME", "RTAI_Engagement")
    SCAN_SELF: bool = _bool("SCAN_SELF")

    # Paths
    LOG_DIR: Path = _ROOT / "logs"
    REPORT_DIR: Path = _ROOT / "reports"
    REMEDIATION_DIR: Path = _ROOT / "remediation"

    @classmethod
    def validate(cls) -> None:
        if not cls.USE_LOCAL_LLM and not cls.OPENAI_API_KEY:
            raise EnvironmentError(
                "OPENAI_API_KEY is not set. Set it in .env or enable USE_LOCAL_LLM=true for offline mode."
            )
        if not cls.USE_LOCAL_OSINT and not cls.TAVILY_API_KEY:
            raise EnvironmentError(
                "TAVILY_API_KEY is not set. Set it in .env or enable USE_LOCAL_OSINT=true for offline mode."
            )
        if not cls.TARGET_SCOPE:
            raise EnvironmentError("TARGET_SCOPE is not set in .env")
        cls.LOG_DIR.mkdir(exist_ok=True)
        cls.REPORT_DIR.mkdir(exist_ok=True)
        cls.REMEDIATION_DIR.mkdir(exist_ok=True)

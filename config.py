"""Uygulama genelindeki yapılandırma ayarları (tek doğruluk kaynağı).

Tüm modüller (`hr_bot.py`, `hr_bot_guvenli.py`, `main.py`, `giskard_scan.py`,
`redteam_benchmark.py`) ortam değişkenlerini yalnızca bu modül üzerinden okur.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR: Path = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

PLACEHOLDER_API_KEYS: frozenset[str] = frozenset(
    {
        "",
        "buraya_api_anahtarinizi_yazin",
        "your_gemini_api_key_here",
    }
)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw.strip())
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw.strip())
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    """Çalışma zamanı ve güvenlik yapılandırması."""

    gemini_api_key: str
    gemini_model: str
    gemini_fallback_model: str
    gemini_temperature: float
    host: str
    port: int
    reload: bool
    trust_proxy_headers: bool
    max_message_length: int
    max_history_turns: int
    session_ttl_seconds: int
    max_sessions: int
    chat_rate_limit_per_minute: int
    scan_rate_limit_per_5min: int
    scan_timeout_seconds: int
    scan_request_delay_seconds: float
    enable_scan_endpoint: bool
    scan_token: str
    admin_api_token: str
    reports_dir: Path
    live_report_path: Path
    sample_report_path: Path
    benchmark_json_path: Path

    @property
    def has_valid_api_key(self) -> bool:
        """API anahtarının şablon dışı bir değer içerip içermediğini döner."""
        return self.gemini_api_key.strip() not in PLACEHOLDER_API_KEYS


def load_settings() -> Settings:
    """Ortam değişkenlerinden güncel `Settings` nesnesi üretir."""
    reports_dir = BASE_DIR / "reports"
    examples_dir = BASE_DIR / "examples"
    return Settings(
        gemini_api_key=os.getenv("GEMINI_API_KEY", "").strip(),
        gemini_model=os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite").strip(),
        gemini_fallback_model=os.getenv("GEMINI_FALLBACK_MODEL", "gemini-3.1-flash-lite").strip(),
        gemini_temperature=_env_float("GEMINI_TEMPERATURE", 0.2),
        host=os.getenv("HOST", "127.0.0.1").strip(),
        port=_env_int("PORT", 8000),
        reload=_env_bool("UVICORN_RELOAD", False),
        trust_proxy_headers=_env_bool("TRUST_PROXY_HEADERS", False),
        max_message_length=_env_int("MAX_MESSAGE_LENGTH", 1000),
        max_history_turns=_env_int("MAX_HISTORY_TURNS", 10),
        session_ttl_seconds=_env_int("SESSION_TTL_SECONDS", 3600),
        max_sessions=_env_int("MAX_SESSIONS", 512),
        chat_rate_limit_per_minute=_env_int("CHAT_RATE_LIMIT_PER_MINUTE", 20),
        scan_rate_limit_per_5min=_env_int("SCAN_RATE_LIMIT_PER_5MIN", 2),
        scan_timeout_seconds=_env_int("SCAN_TIMEOUT_SECONDS", 600),
        scan_request_delay_seconds=_env_float("SCAN_REQUEST_DELAY_SECONDS", 1.2),
        enable_scan_endpoint=_env_bool("ENABLE_SCAN_ENDPOINT", True),
        scan_token=os.getenv("SCAN_TOKEN", "").strip(),
        admin_api_token=os.getenv("ADMIN_API_TOKEN", "").strip(),
        reports_dir=reports_dir,
        live_report_path=reports_dir / "giskard_zafiyet_raporu.html",
        sample_report_path=examples_dir / "ornek_giskard_raporu.html",
        benchmark_json_path=examples_dir / "karsilastirma_sonuclari.json",
    )


settings: Settings = load_settings()

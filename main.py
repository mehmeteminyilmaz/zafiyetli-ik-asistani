"""FastAPI Arka Uç Sunucusu — Zafiyetli & Güvenli İK Asistanı ve Giskard Raporlayıcı.

Güvenlik ve güvenilirlik özellikleri:
- Aynı origin üzerinden servis edildiği için gevşek CORS (`*` + credentials) kullanılmaz.
- Girdi uzunluk sınırları (`MAX_MESSAGE_LENGTH`), çok turlu geçmiş doğrulaması ve IP hız sınırı (rate limit) uygulanır.
- Ham istisna/sağlayıcı hata mesajları istemciye sızdırılmaz; uygun HTTP durum kodları (400/403/429/502/503) döner.
- Tarama durumu (`ScanStateManager`) `threading.Lock` ile korunur, yeni taramada `completed` bayrağı sıfırlanır
  ve alt süreç `SCAN_TIMEOUT_SECONDS` zaman aşımıyla sınırlandırılır.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from config import BASE_DIR, load_settings
from hr_bot import ask_hr_bot
from hr_bot_guvenli import ask_secure_hr_bot_detailed
from leak_detector import detect_sensitive_leak
from llm_core import (
    BotAuthenticationError,
    BotConfigurationError,
    BotRateLimitError,
    BotUpstreamError,
)
from probes import ChatTurn

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

STATIC_DIR = BASE_DIR / "static"
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost", "testclient"})


class SlidingWindowRateLimiter:
    """IP bazlı, iş parçacığı güvenli (thread-safe) kayan pencere hız sınırlayıcısı."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._hits: dict[str, deque[float]] = {}

    def allow(self, key: str, max_requests: int, window_seconds: float) -> bool:
        if max_requests <= 0:
            return True
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            bucket = self._hits.setdefault(key, deque())
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= max_requests:
                return False
            bucket.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


@dataclass
class ScanStatusSnapshot:
    """Tarama durumunun anlık kopyası."""

    is_running: bool = False
    last_result: str = "Henüz tarama başlatılmadı."
    completed: bool = False
    failed: bool = False


class ScanStateManager:
    """Giskard arka plan tarama durumunu `threading.Lock` ile güvenli yönetir."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._state = ScanStatusSnapshot()

    def try_begin_scan(self, target: str) -> bool:
        """Tarama çalışmıyorsa yeni tarama başlatır ve önceki `completed` bayrağını sıfırlar."""
        with self._lock:
            if self._state.is_running:
                return False
            self._state = ScanStatusSnapshot(
                is_running=True,
                last_result=f"Giskard otomatik taraması çalışıyor ({target})...",
                completed=False,
                failed=False,
            )
            return True

    def mark_succeeded(self, message: str) -> None:
        with self._lock:
            self._state.is_running = False
            self._state.completed = True
            self._state.failed = False
            self._state.last_result = message

    def mark_failed(self, message: str) -> None:
        with self._lock:
            self._state.is_running = False
            self._state.completed = False
            self._state.failed = True
            self._state.last_result = message

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "is_running": self._state.is_running,
                "last_result": self._state.last_result,
                "completed": self._state.completed,
                "failed": self._state.failed,
            }


rate_limiter = SlidingWindowRateLimiter()
scan_manager = ScanStateManager()

app = FastAPI(
    title="TechCorp İK Asistanı — Yapay Zeka Güvenlik Laboratuvarı",
    description="Zafiyetli ve Güvenli İK Botu + Giskard Otomatik Güvenlik Taraması",
    version="2.0.0",
)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next: Any) -> Response:
    """Temel güvenlik başlıklarını (CSP, X-Content-Type-Options, X-Frame-Options) ekler."""
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # Giskard'ın ürettiği bağımsız HTML raporu kendi gömülü stil/betiklerini içerdiğinden
    # sıkı CSP yalnızca ana uygulama ve statik varlıklara uygulanır.
    if not request.url.path.startswith("/report"):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self';"
        )
    return response


class HistoryItem(BaseModel):
    """Konuşma geçmişindeki tek bir mesaj öğesi."""

    role: Literal["user", "model"]
    content: str = Field(..., min_length=1, max_length=2000)


class ChatRequest(BaseModel):
    """Sohbet uç noktası istek şeması."""

    message: str = Field(..., min_length=1, max_length=1000)
    mode: Literal["vulnerable", "secure"] = "vulnerable"
    history: list[HistoryItem] = Field(default_factory=list, max_length=20)

    @field_validator("message")
    @classmethod
    def validate_non_blank(cls, value: str) -> str:
        cfg = load_settings()
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Mesaj boş veya yalnızca boşluk karakterlerinden oluşamaz.")
        if len(cleaned) > cfg.max_message_length:
            raise ValueError(f"Mesaj uzunluğu en fazla {cfg.max_message_length} karakter olabilir.")
        return cleaned


class ChatResponse(BaseModel):
    """Sohbet uç noktası yanıt şeması."""

    reply: str
    mode: Literal["vulnerable", "secure"]
    is_leak: bool = False
    leaked_categories: list[str] = Field(default_factory=list)
    guard_blocked: bool = False
    triggered_rules: list[str] = Field(default_factory=list)


class ScanRequest(BaseModel):
    """Tarama başlatma isteği şeması."""

    target: Literal["vulnerable", "secure"] = "vulnerable"


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@app.get("/health")
def health_endpoint() -> dict[str, Any]:
    """Sunucu ve API yapılandırma sağlığını gerçek zamanlı döner."""
    cfg = load_settings()
    return {
        "status": "ok" if cfg.has_valid_api_key else "degraded",
        "api_key_configured": cfg.has_valid_api_key,
        "model": cfg.gemini_model,
        "live_report_exists": cfg.live_report_path.exists(),
        "sample_report_exists": cfg.sample_report_path.exists(),
    }


@app.post("/api/chat", response_model=ChatResponse)
def chat_endpoint(req: ChatRequest, request: Request) -> ChatResponse:
    """Kullanıcı mesajını seçilen moddaki (`vulnerable` / `secure`) İK botuna iletir."""
    cfg = load_settings()
    ip = _client_ip(request)
    if not rate_limiter.allow(f"chat:{ip}", cfg.chat_rate_limit_per_minute, 60.0):
        raise HTTPException(
            status_code=429,
            detail="Çok fazla mesaj gönderildi. Lütfen bir dakika bekleyip tekrar deneyin.",
        )

    turns = [ChatTurn(role=item.role, content=item.content) for item in req.history]

    try:
        if req.mode == "secure":
            sec_res = ask_secure_hr_bot_detailed(req.message, history=turns)
            leak_check = detect_sensitive_leak(sec_res.reply)
            return ChatResponse(
                reply=sec_res.reply,
                mode="secure",
                is_leak=leak_check.is_leak,
                leaked_categories=leak_check.categories,
                guard_blocked=sec_res.blocked_by_input_guard or sec_res.blocked_by_output_dlp,
                triggered_rules=sec_res.triggered_rules,
            )

        reply = ask_hr_bot(req.message, history=turns)
        leak_check = detect_sensitive_leak(reply)
        return ChatResponse(
            reply=reply,
            mode="vulnerable",
            is_leak=leak_check.is_leak,
            leaked_categories=leak_check.categories,
            guard_blocked=False,
            triggered_rules=[],
        )

    except BotConfigurationError as exc:
        logger.error("Yapılandırma hatası: %s", exc)
        raise HTTPException(
            status_code=503,
            detail="Sunucu API anahtarı yapılandırılmamış. Lütfen .env dosyasını kontrol edin.",
        ) from exc
    except BotAuthenticationError as exc:
        logger.error("API kimlik doğrulama hatası: %s", exc)
        raise HTTPException(
            status_code=502,
            detail="Yapay zeka servisi kimlik doğrulaması başarısız oldu.",
        ) from exc
    except BotRateLimitError as exc:
        logger.warning("Üst sağlayıcı kota sınırı: %s", exc)
        raise HTTPException(
            status_code=429,
            detail="Yapay zeka API kotası aşıldı. Lütfen biraz bekleyip tekrar deneyin.",
        ) from exc
    except BotUpstreamError as exc:
        logger.error("Üst sağlayıcı hatası: %s", exc)
        raise HTTPException(
            status_code=502,
            detail="Yapay zeka servisinden yanıt alınamadı. Lütfen tekrar deneyin.",
        ) from exc


def _run_giskard_subprocess(target: str, timeout_seconds: int) -> None:
    """Arka plan iş parçacığında `giskard_scan.py` betiğini zaman aşımı sınırıyla çalıştırır."""
    script_path = BASE_DIR / "giskard_scan.py"
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"

    try:
        result = subprocess.run(
            [sys.executable, str(script_path), "--target", target],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(BASE_DIR),
            env=env,
            timeout=timeout_seconds,
        )
        if result.returncode == 0:
            scan_manager.mark_succeeded("Giskard taraması başarıyla tamamlandı. Rapor hazır.")
        else:
            logger.error("Giskard alt süreç hatası (kod=%s): %s", result.returncode, result.stderr)
            scan_manager.mark_failed("Tarama tamamlanamadı. Detaylar sunucu günlüklerine kaydedildi.")
    except subprocess.TimeoutExpired:
        logger.error("Giskard taraması %d saniyelik zaman aşımı sınırını aştı.", timeout_seconds)
        scan_manager.mark_failed(f"Tarama zaman aşımına uğradı ({timeout_seconds} sn).")
    except Exception:
        logger.exception("Giskard taraması çalıştırılırken beklenmeyen hata oluştu.")
        scan_manager.mark_failed("Tarama sırasında beklenmeyen bir sunucu hatası oluştu.")


def _verify_scan_permission(request: Request) -> None:
    """Tarama uç noktasını yerel istemci ve/veya `SCAN_TOKEN` ile korur."""
    cfg = load_settings()
    if not cfg.enable_scan_endpoint:
        raise HTTPException(status_code=403, detail="Web üzerinden tarama tetikleme devre dışı bırakılmış.")

    client_host = _client_ip(request)
    provided_token = request.headers.get("X-Scan-Token", "")

    if cfg.scan_token:
        if not provided_token or not hmac.compare_digest(provided_token, cfg.scan_token):
            raise HTTPException(status_code=403, detail="Geçersiz veya eksik tarama yetki anahtarı (X-Scan-Token).")
    elif client_host not in LOOPBACK_HOSTS:
        raise HTTPException(
            status_code=403,
            detail="Güvenlik nedeniyle tarama yalnızca yerel makineden (localhost) başlatılabilir.",
        )


@app.post("/api/run-scan")
def run_scan_endpoint(
    request: Request,
    scan_req: ScanRequest | None = None,
) -> dict[str, str]:
    """Gerçek `giskard.scan()` sürecini arka planda güvenli şekilde başlatır."""
    _verify_scan_permission(request)
    cfg = load_settings()
    ip = _client_ip(request)

    if not cfg.has_valid_api_key:
        raise HTTPException(status_code=503, detail="Tarama başlatılamadı: GEMINI_API_KEY tanımlı değil.")

    target = scan_req.target if scan_req else "vulnerable"
    current = scan_manager.snapshot()
    if current["is_running"]:
        return {"status": "already_running", "message": "Tarama zaten devam ediyor."}

    if not rate_limiter.allow(f"scan:{ip}", cfg.scan_rate_limit_per_5min, 300.0):
        raise HTTPException(
            status_code=429,
            detail="Tarama çok sık tetiklendi. Lütfen birkaç dakika bekleyin.",
        )

    if not scan_manager.try_begin_scan(target=target):
        return {"status": "already_running", "message": "Tarama zaten devam ediyor."}

    worker = threading.Thread(
        target=_run_giskard_subprocess,
        args=(target, cfg.scan_timeout_seconds),
        daemon=True,
    )
    worker.start()
    return {"status": "started", "message": f"Giskard güvenlik taraması başlatıldı ({target})."}


@app.get("/api/scan-status")
def get_scan_status() -> dict[str, Any]:
    """Anlık tarama durumunu döner."""
    return scan_manager.snapshot()


@app.get("/api/benchmark")
def get_benchmark_results() -> dict[str, Any]:
    """Kaydedilmiş öncesi/sonrası kırmızı takım kıyaslama verisini döner."""
    cfg = load_settings()
    if not cfg.benchmark_json_path.exists():
        raise HTTPException(
            status_code=404,
            detail="Henüz kıyaslama çıktısı bulunmuyor. `python redteam_benchmark.py` komutunu çalıştırın.",
        )
    try:
        data: dict[str, Any] = json.loads(cfg.benchmark_json_path.read_text(encoding="utf-8"))
        return data
    except Exception as exc:
        logger.error("Kıyaslama JSON dosyası okunamadı: %s", exc)
        raise HTTPException(status_code=500, detail="Kıyaslama verisi okunamadı.") from exc


@app.get("/report", response_model=None)
def get_report(sample: bool = False) -> Response:
    """Canlı Giskard HTML raporunu (veya mevcutsa örnek raporu) döner."""
    cfg = load_settings()
    if not sample and cfg.live_report_path.exists():
        return FileResponse(cfg.live_report_path, media_type="text/html")
    if cfg.sample_report_path.exists():
        return FileResponse(cfg.sample_report_path, media_type="text/html")
    return HTMLResponse(
        content=(
            "<!doctype html><html lang='tr'><head><meta charset='utf-8'>"
            "<title>Rapor Bulunamadı</title></head><body style='font-family:sans-serif;padding:2rem'>"
            "<h2>Henüz Giskard güvenlik raporu üretilmedi.</h2>"
            "<p>Terminalden <code>python giskard_scan.py</code> çalıştırabilir veya arayüzden "
            "taramayı başlatabilirsiniz.</p><p><a href='/'>Ana Sayfaya Dön</a></p></body></html>"
        ),
        status_code=404,
    )


if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", response_model=None)
def read_root() -> Response:
    """Ana web arayüzünü sunar."""
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file, media_type="text/html")
    return HTMLResponse("<h1>TechCorp İK Asistanı API Çalışıyor</h1>")


if __name__ == "__main__":
    import uvicorn

    cfg = load_settings()
    if cfg.host in {"0.0.0.0", "::"}:
        logger.warning(
            "GÜVENLİK UYARISI: Sunucu tüm ağ arayüzlerine (%s) açık başlatılıyor! "
            "Bu eğitim uygulaması kimlik doğrulaması içermez; dış ağa açmayın.",
            cfg.host,
        )
    uvicorn.run("main:app", host=cfg.host, port=cfg.port, reload=cfg.reload)

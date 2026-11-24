"""FastAPI Arka Uç Sunucusu — Zafiyetli & Güvenli İK Asistanı ve Giskard Raporlayıcı.

Güvenlik ve güvenilirlik özellikleri:
- Konuşma geçmişi istemciden kabul edilmez (`history poisoning` önlemi); sunucu tarafında
  TTL ve kapasite sınırlı `ServerSessionStore` içinde oturum kimliği (`session_id`) ile tutulur.
- Model dışı (out-of-band) deterministik RBAC örneği `/api/admin/audit-records` uç noktasında
  `verify_admin_access` / `get_authorized_admin_records` ile gerçek iş akışına bağlıdır.
- `/report` uç noktası `Content-Security-Policy: sandbox allow-scripts` ile benzersiz opak
  origin'de izole edilir; ana uygulama `script-src 'self'` CSP ile korunur.
- Hız sınırlayıcı (`SlidingWindowRateLimiter`) süresi dolan anahtarları temizler ve bellek sınırı uygular.
- Loopback kontrolü yalnızca gerçek IP adreslerini (`127.0.0.1`, `::1`) kabul eder ve
  reverse-proxy başlıkları (`X-Forwarded-For`, `Forwarded`, `X-Real-IP`) varsa doğrudan
  loopback varsayımını reddeder.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
import uuid
from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from config import BASE_DIR, load_settings
from hr_bot import ask_hr_bot
from hr_bot_guvenli import ask_secure_hr_bot_detailed, get_authorized_admin_records
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
# Üretim kodunda yalnızca gerçek geri döngü (loopback) IP sabitleri yer alır ("testclient" eklenmez)
LOOPBACK_IPS = frozenset({"127.0.0.1", "::1"})
PROXY_HEADERS = ("x-forwarded-for", "forwarded", "x-real-ip")
_SESSION_ID_RE = re.compile(r"^[a-f0-9]{32}$")


class SlidingWindowRateLimiter:
    """Bellek sınırı ve otomatik temizlik içeren iş parçacığı güvenli kayan pencere hız sınırlayıcısı."""

    def __init__(self, max_keys: int = 4096, cleanup_interval_seconds: float = 60.0) -> None:
        self._lock = threading.Lock()
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()
        self._max_keys = max_keys
        self._cleanup_interval = cleanup_interval_seconds
        self._last_cleanup = time.monotonic()

    def _prune_stale_unlocked(self, now: float, max_window: float) -> None:
        cutoff = now - max(max_window, self._cleanup_interval)
        stale_keys = [k for k, q in self._hits.items() if not q or q[-1] < cutoff]
        for k in stale_keys:
            del self._hits[k]
        self._last_cleanup = now

    def allow(self, key: str, max_requests: int, window_seconds: float) -> bool:
        if max_requests <= 0:
            return True
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            if now - self._last_cleanup >= self._cleanup_interval:
                self._prune_stale_unlocked(now, window_seconds)

            bucket = self._hits.get(key)
            if bucket is None:
                if len(self._hits) >= self._max_keys:
                    self._prune_stale_unlocked(now, window_seconds)
                if len(self._hits) >= self._max_keys:
                    self._hits.popitem(last=False)
                bucket = deque()
                self._hits[key] = bucket
            else:
                self._hits.move_to_end(key)

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
class _SessionEntry:
    mode: str
    turns: list[ChatTurn]
    updated_at: float


class ServerSessionStore:
    """Konuşma geçmişini istemci manipülasyonuna karşı sunucu belleğinde güvenli tutar."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: OrderedDict[str, _SessionEntry] = OrderedDict()

    def _prune_unlocked(self, now: float, ttl_seconds: int, max_sessions: int) -> None:
        cutoff = now - ttl_seconds
        expired = [sid for sid, entry in self._sessions.items() if entry.updated_at < cutoff]
        for sid in expired:
            del self._sessions[sid]
        while len(self._sessions) > max_sessions:
            self._sessions.popitem(last=False)

    def get_or_create(self, session_id: str | None, mode: str) -> tuple[str, list[ChatTurn]]:
        cfg = load_settings()
        now = time.monotonic()
        valid_id = session_id if (session_id and _SESSION_ID_RE.match(session_id)) else uuid.uuid4().hex

        with self._lock:
            self._prune_unlocked(now, cfg.session_ttl_seconds, cfg.max_sessions)
            entry = self._sessions.get(valid_id)
            if entry is None or entry.mode != mode:
                # Mod değiştiğinde veya oturum yoksa temiz geçmiş başlatılır
                self._sessions[valid_id] = _SessionEntry(mode=mode, turns=[], updated_at=now)
                self._sessions.move_to_end(valid_id)
                return valid_id, []
            entry.updated_at = now
            self._sessions.move_to_end(valid_id)
            return valid_id, list(entry.turns)

    def append_exchange(self, session_id: str, mode: str, user_msg: str, model_reply: str) -> None:
        cfg = load_settings()
        now = time.monotonic()
        max_items = max(2, cfg.max_history_turns * 2)
        with self._lock:
            entry = self._sessions.get(session_id)
            if entry is None or entry.mode != mode:
                entry = _SessionEntry(mode=mode, turns=[], updated_at=now)
                self._sessions[session_id] = entry
            entry.turns.append(ChatTurn(role="user", content=user_msg))
            entry.turns.append(ChatTurn(role="model", content=model_reply))
            if len(entry.turns) > max_items:
                entry.turns = entry.turns[-max_items:]
            entry.updated_at = now
            self._sessions.move_to_end(session_id)

    def clear_session(self, session_id: str | None) -> None:
        if not session_id:
            return
        with self._lock:
            self._sessions.pop(session_id, None)

    def reset_all(self) -> None:
        with self._lock:
            self._sessions.clear()


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
session_store = ServerSessionStore()
scan_manager = ScanStateManager()

app = FastAPI(
    title="TechCorp İK Asistanı — Yapay Zeka Güvenlik Laboratuvarı",
    description="Zafiyetli ve Güvenli İK Botu + Giskard Otomatik Güvenlik Taraması",
    version="2.1.0",
)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next: Any) -> Response:
    """Ana uygulama ve izole Giskard raporu için uygun CSP ve güvenlik başlıklarını uygular."""
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    if request.url.path.startswith("/report"):
        # `sandbox allow-scripts` (allow-same-origin OLMADAN) raporu opak `null` origin içine hapseder:
        # Giskard'ın sekme geçişleri ve gömülü stilleri çalışır ancak rapor içindeki hiçbir betik
        # ana uygulamanın origin'ine, çerezlerine veya API uç noktalarına erişemez.
        response.headers["Content-Security-Policy"] = (
            "sandbox allow-scripts; "
            "default-src 'none'; "
            "style-src 'unsafe-inline'; "
            "script-src 'unsafe-inline'; "
            "img-src data:; "
            "base-uri 'none'; "
            "form-action 'none';"
        )
    else:
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


class ChatRequest(BaseModel):
    """Sohbet uç noktası istek şeması.

    Güvenlik notu: `history` ve `enable_input_guard` istemciden KABUL EDİLMEZ;
    oturum geçmişi ve girdi kalkanı durumu yalnızca sunucu tarafından kontrol edilir.
    """

    message: str = Field(..., min_length=1, max_length=1000)
    mode: Literal["vulnerable", "secure"] = "vulnerable"
    session_id: str | None = Field(default=None, max_length=64)

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
    session_id: str
    is_leak: bool = False
    leaked_categories: list[str] = Field(default_factory=list)
    guard_blocked: bool = False
    triggered_rules: list[str] = Field(default_factory=list)


class ResetSessionRequest(BaseModel):
    """Sunucu taraflı oturum geçmişi sıfırlama isteği."""

    session_id: str | None = Field(default=None, max_length=64)


class ScanRequest(BaseModel):
    """Tarama başlatma isteği şeması."""

    target: Literal["vulnerable", "secure"] = "vulnerable"


def _has_proxy_headers(request: Request) -> bool:
    return any(h in request.headers for h in PROXY_HEADERS)


def _effective_client_ip(request: Request) -> str:
    """Hız sınırlaması için istemci IP'sini belirler.

    `TRUST_PROXY_HEADERS=true` olduğunda `X-Forwarded-For` zincirinin en solundaki (istemcinin
    kolayca sahteleyebileceği) değer DEĞİL, `TRUSTED_PROXY_COUNT` sayısına göre sağdan
    güvenilir vekil sunucunun eklediği IP okunur.
    """
    cfg = load_settings()
    if cfg.trust_proxy_headers:
        xff = request.headers.get("x-forwarded-for", "")
        if xff:
            chain = [ip.strip() for ip in xff.split(",") if ip.strip()]
            if chain:
                idx = max(0, len(chain) - cfg.trusted_proxy_count)
                return chain[idx]
        real_ip = request.headers.get("x-real-ip", "").strip()
        if real_ip:
            return real_ip
    return request.client.host if request.client else "unknown"


def _is_direct_loopback_request(request: Request) -> bool:
    """İsteğin bir reverse proxy üzerinden değil, doğrudan yerel makineden geldiğini doğrular."""
    if _has_proxy_headers(request):
        return False
    direct_host = request.client.host if request.client else ""
    return direct_host in LOOPBACK_IPS


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
        "rbac_admin_configured": bool(cfg.admin_api_token),
    }


@app.post("/api/chat/reset")
def reset_chat_session(req: ResetSessionRequest) -> dict[str, str]:
    """İlgili oturumun sunucu belleğindeki konuşma geçmişini temizler."""
    session_store.clear_session(req.session_id)
    return {"status": "cleared", "session_id": uuid.uuid4().hex}


@app.post("/api/chat", response_model=ChatResponse)
def chat_endpoint(req: ChatRequest, request: Request) -> ChatResponse:
    """Kullanıcı mesajını sunucu taraflı oturum geçmişiyle seçilen İK botuna iletir."""
    cfg = load_settings()
    ip = _effective_client_ip(request)
    if not rate_limiter.allow(f"chat:{ip}", cfg.chat_rate_limit_per_minute, 60.0):
        raise HTTPException(
            status_code=429,
            detail="Çok fazla mesaj gönderildi. Lütfen bir dakika bekleyip tekrar deneyin.",
        )

    session_id, turns = session_store.get_or_create(req.session_id, req.mode)

    try:
        if req.mode == "secure":
            sec_res = ask_secure_hr_bot_detailed(
                req.message,
                history=turns,
                enable_input_guard=cfg.secure_enable_input_guard,
            )
            leak_check = detect_sensitive_leak(sec_res.reply)
            guard_blocked = sec_res.blocked_by_input_guard or sec_res.blocked_by_output_dlp
            if not guard_blocked:
                session_store.append_exchange(session_id, "secure", req.message, sec_res.reply)
            return ChatResponse(
                reply=sec_res.reply,
                mode="secure",
                session_id=session_id,
                is_leak=leak_check.is_leak,
                leaked_categories=leak_check.categories,
                guard_blocked=guard_blocked,
                triggered_rules=sec_res.triggered_rules,
            )

        reply = ask_hr_bot(req.message, history=turns)
        leak_check = detect_sensitive_leak(reply)
        session_store.append_exchange(session_id, "vulnerable", req.message, reply)
        return ChatResponse(
            reply=reply,
            mode="vulnerable",
            session_id=session_id,
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


@app.get("/api/admin/audit-records")
def admin_audit_records_endpoint(request: Request) -> dict[str, Any]:
    """Model dışı (Out-of-Band RBAC) yetkili veri erişim uç noktası.

    Hassas yönetim kayıtları LLM bağlamına konmak yerine bu uç noktada hız sınırı,
    `X-Admin-Token` ve sabit-zamanlı `verify_admin_access` ile deterministik doğrulanır.
    """
    cfg = load_settings()
    ip = _effective_client_ip(request)
    if not rate_limiter.allow(f"admin:{ip}", cfg.admin_rate_limit_per_minute, 60.0):
        raise HTTPException(
            status_code=429,
            detail="Çok fazla yetkili kayıt sorgusu gönderildi. Lütfen bir dakika bekleyin.",
        )

    if not cfg.admin_api_token:
        raise HTTPException(
            status_code=503,
            detail="Yönetici RBAC servisi yapılandırılmamış (ADMIN_API_TOKEN tanımlı değil).",
        )

    provided_token = request.headers.get("X-Admin-Token", "")
    try:
        return get_authorized_admin_records(provided_token, cfg.admin_api_token)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


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
    """Tarama uç noktasını doğrudan yerel istemci ve/veya `SCAN_TOKEN` ile korur."""
    cfg = load_settings()
    if not cfg.enable_scan_endpoint:
        raise HTTPException(status_code=403, detail="Web üzerinden tarama tetikleme devre dışı bırakılmış.")

    provided_token = request.headers.get("X-Scan-Token", "")
    if cfg.scan_token:
        if not provided_token or not hmac.compare_digest(provided_token, cfg.scan_token):
            raise HTTPException(status_code=403, detail="Geçersiz veya eksik tarama yetki anahtarı (X-Scan-Token).")
    elif not _is_direct_loopback_request(request):
        raise HTTPException(
            status_code=403,
            detail=(
                "Güvenlik nedeniyle tarama yalnızca doğrudan yerel makineden (localhost) başlatılabilir. "
                "Reverse proxy arkasında çalıştırıyorsanız SCAN_TOKEN tanımlayın."
            ),
        )


@app.post("/api/run-scan")
def run_scan_endpoint(
    request: Request,
    scan_req: ScanRequest | None = None,
) -> dict[str, str]:
    """Gerçek `giskard.scan()` sürecini arka planda güvenli şekilde başlatır."""
    _verify_scan_permission(request)
    cfg = load_settings()
    ip = _effective_client_ip(request)

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

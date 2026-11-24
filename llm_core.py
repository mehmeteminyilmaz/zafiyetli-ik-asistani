"""Paylaşılan Gemini API istemcisi, çok turlu geçmiş dönüştürücüsü ve hata sınıfları.

Bu modül import edildiğinde konsola hiçbir çıktı basmaz (`print` kullanılmaz) ve
ham API/sistem hatalarını son kullanıcıya sızdırmak yerine tipli istisnalar fırlatır.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence

from google import genai
from google.genai import errors as genai_errors
from google.genai import types

from config import Settings, load_settings
from probes import ChatTurn

logger = logging.getLogger(__name__)

SAFETY_BLOCKED_FALLBACK_TEXT: str = (
    "Üzgünüm, güvenlik filtreleri nedeniyle bu iletiye yanıt üretilemedi. "
    "Lütfen kurumsal İK prosedürleri çerçevesinde sorunuzu yeniden iletin."
)


class BotError(Exception):
    """İK botu katmanındaki tüm kontrollü hataların taban sınıfı."""


class BotConfigurationError(BotError):
    """API anahtarı eksik veya geçersiz şablon değerinde olduğunda fırlatılır."""


class BotAuthenticationError(BotError):
    """API anahtarı sağlayıcı tarafından reddedildiğinde (401/403) fırlatılır."""


class BotRateLimitError(BotError):
    """API kota/istek sınırı (429) aşıldığında fırlatılır."""


class BotUpstreamError(BotError):
    """Üst sağlayıcı (503, ağ hatası, geçersiz model vb.) kaynaklı hatalarda fırlatılır."""


_cached_client: genai.Client | None = None
_cached_api_key: str | None = None


def get_genai_client(cfg: Settings | None = None) -> genai.Client:
    """Geçerli `GEMINI_API_KEY` ile tembel (lazy) `genai.Client` döndürür."""
    global _cached_client, _cached_api_key
    active_cfg = cfg or load_settings()
    if not active_cfg.has_valid_api_key:
        logger.error("GEMINI_API_KEY tanımlanmamış veya şablon değerinde bırakılmış.")
        raise BotConfigurationError("Sunucu API anahtarı yapılandırılmamış.")

    if _cached_client is None or _cached_api_key != active_cfg.gemini_api_key:
        _cached_client = genai.Client(
            api_key=active_cfg.gemini_api_key,
            http_options=types.HttpOptions(timeout=25_000),
        )
        _cached_api_key = active_cfg.gemini_api_key
    return _cached_client


def build_contents(
    user_message: str,
    history: Sequence[ChatTurn] | None = None,
    max_turns: int | None = None,
) -> list[types.Content]:
    """Konuşma geçmişini ve son kullanıcı mesajını `types.Content` listesine çevirir."""
    cfg = load_settings()
    limit = max_turns if max_turns is not None else cfg.max_history_turns
    contents: list[types.Content] = []

    if history:
        trimmed = list(history)[-limit * 2 :] if limit > 0 else []
        for turn in trimmed:
            role = "model" if turn.role in {"model", "assistant", "bot"} else "user"
            if turn.content and turn.content.strip():
                contents.append(
                    types.Content(
                        role=role,
                        parts=[types.Part.from_text(text=turn.content)],
                    )
                )

    contents.append(
        types.Content(
            role="user",
            parts=[types.Part.from_text(text=user_message)],
        )
    )
    return contents


def generate_gemini_reply(
    user_message: str,
    system_instruction: str,
    history: Sequence[ChatTurn] | None = None,
    model_name: str | None = None,
    temperature: float | None = None,
    client_override: genai.Client | None = None,
) -> str:
    """Gemini modelinden çok turlu yanıt üretir; hata türlerini ayrıştırır."""
    cfg = load_settings()
    active_client = client_override or get_genai_client(cfg)

    primary = (model_name or cfg.gemini_model).strip()
    candidates: list[str] = [primary]
    if cfg.gemini_fallback_model and cfg.gemini_fallback_model not in candidates:
        candidates.append(cfg.gemini_fallback_model)

    temp = cfg.gemini_temperature if temperature is None else temperature
    contents = build_contents(user_message=user_message, history=history, max_turns=cfg.max_history_turns)

    saw_rate_limit = False

    for idx, candidate_model in enumerate(candidates):
        try:
            response = active_client.models.generate_content(
                model=candidate_model,
                contents=contents,
                config=types.GenerateContentConfig(
                    system_instruction=system_instruction,
                    temperature=temp,
                ),
            )
            # Güvenlik filtresi veya boş aday durumunda response.text None dönebilir
            text = getattr(response, "text", None)
            if text is None or not str(text).strip():
                logger.warning("Model (%s) boş yanıt veya güvenlik engeli döndürdü.", candidate_model)
                return SAFETY_BLOCKED_FALLBACK_TEXT
            return str(text)

        except genai_errors.APIError as api_err:
            status_code = getattr(api_err, "code", None)
            logger.warning(
                "Gemini API hatası (model=%s, kod=%s, deneme=%d/%d): %s",
                candidate_model,
                status_code,
                idx + 1,
                len(candidates),
                api_err,
            )
            # Kimlik doğrulama / yetki hatalarında yedek modele geçmek anlamsızdır
            if status_code in {401, 403}:
                raise BotAuthenticationError("Gemini API kimlik doğrulaması başarısız oldu.") from api_err

            if status_code == 429:
                saw_rate_limit = True
                if idx + 1 < len(candidates):
                    continue
                raise BotRateLimitError("Model istek kotası aşıldı, lütfen biraz bekleyip tekrar deneyin.") from api_err

            # 404 (model bulunamadı) veya 500/503 (geçici yoğunluk) durumlarında yedek modeli dene
            if status_code in {404, 500, 502, 503, 504} and idx + 1 < len(candidates):
                continue

            raise BotUpstreamError("Yapay zeka servisinden geçerli bir yanıt alınamadı.") from api_err

        except BotError:
            raise
        except Exception as exc:
            logger.exception("Gemini çağrısı sırasında beklenmeyen iletişim hatası (model=%s).", candidate_model)
            if idx + 1 < len(candidates):
                continue
            if saw_rate_limit:
                raise BotRateLimitError("Model istek kotası aşıldı, lütfen biraz bekleyip tekrar deneyin.") from exc
            raise BotUpstreamError("Yapay zeka servisine bağlanırken bir hata oluştu.") from exc

    raise BotUpstreamError("Uygun yapay zeka modeli bulunamadı.")

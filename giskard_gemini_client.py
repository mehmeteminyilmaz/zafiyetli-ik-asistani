"""Giskard LLM dedektörleri için Google Gemini (`google-genai`) istemci adaptörü.

Giskard'ın LLM destekli dedektörleri (`llm_information_disclosure` vb.) varsayılan
olarak OpenAI API anahtarı bekler. Bu modül, Giskard'ın resmi `LLMClient` soyut
sınıfını `google-genai` SDK'sı üzerinde gerçekleyerek:
- Gereksinim üretimi (`TestcaseRequirementsGenerator`),
- Çekişmeli saldırı girdisi üretimi (`AdversarialDataGenerator`),
- LLM-hakem değerlendirmesi (`RequirementEvaluator`)
adımlarının tamamının doğrudan Gemini modeli üzerinden çalışmasını sağlar.
"""

from __future__ import annotations

import json
import logging
import re
import time
import warnings
from collections.abc import Sequence
from typing import Any

from giskard.llm.client import ChatMessage, LLMClient, set_default_client
from google import genai
from google.genai import errors as genai_errors
from google.genai import types

from config import Settings, load_settings
from llm_core import get_genai_client

logger = logging.getLogger(__name__)

_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE)


def _clean_json_text(raw_text: str) -> str:
    """Model çıktısındaki olası markdown kod çitlerini temizleyip geçerli JSON metni döner."""
    stripped = raw_text.strip()
    try:
        parsed = json.loads(stripped, strict=False)
        return json.dumps(parsed, ensure_ascii=False)
    except json.JSONDecodeError:
        pass

    fence_match = _JSON_FENCE_RE.search(stripped)
    if fence_match:
        candidate = fence_match.group(1).strip()
        try:
            parsed = json.loads(candidate, strict=False)
            return json.dumps(parsed, ensure_ascii=False)
        except json.JSONDecodeError:
            pass

    if "{" in stripped and "}" in stripped:
        start = stripped.index("{")
        end = stripped.rfind("}") + 1
        if start < end:
            candidate = stripped[start:end]
            try:
                parsed = json.loads(candidate, strict=False)
                return json.dumps(parsed, ensure_ascii=False)
            except json.JSONDecodeError:
                pass

    return stripped


class GeminiGiskardClient(LLMClient):
    """Giskard `LLMClient` arayüzünün `google-genai` tabanlı gerçeklemesi."""

    def __init__(
        self,
        model: str | None = None,
        fallback_model: str | None = None,
        request_delay_seconds: float | None = None,
        max_retries: int = 6,
        genai_client: genai.Client | None = None,
    ) -> None:
        cfg: Settings = load_settings()
        self.model = (model or cfg.gemini_model).strip()
        self.fallback_model = (fallback_model or cfg.gemini_fallback_model).strip()
        self.request_delay_seconds = (
            cfg.scan_request_delay_seconds if request_delay_seconds is None else request_delay_seconds
        )
        self.max_retries = max_retries
        self._client = genai_client or get_genai_client(cfg)

    def _convert_messages(
        self, messages: Sequence[ChatMessage]
    ) -> tuple[str | None, list[types.Content]]:
        """Giskard `ChatMessage` dizisini Gemini `system_instruction` + `Content` yapısına dönüştürür."""
        system_parts: list[str] = []
        contents: list[types.Content] = []

        for msg in messages:
            content_text = msg.content or ""
            if msg.role == "system":
                if content_text.strip():
                    system_parts.append(content_text.strip())
            elif msg.role == "assistant":
                contents.append(
                    types.Content(
                        role="model",
                        parts=[types.Part.from_text(text=content_text)],
                    )
                )
            else:
                contents.append(
                    types.Content(
                        role="user",
                        parts=[types.Part.from_text(text=content_text)],
                    )
                )

        if not contents and system_parts:
            contents.append(
                types.Content(
                    role="user",
                    parts=[types.Part.from_text(text="\n\n".join(system_parts))],
                )
            )
            return None, contents

        system_instruction = "\n\n".join(system_parts) if system_parts else None
        return system_instruction, contents

    def complete(
        self,
        messages: Sequence[ChatMessage],
        temperature: float = 0.2,
        max_tokens: int | None = None,
        caller_id: str | None = None,
        seed: int | None = None,
        format: Any = None,
    ) -> ChatMessage:
        """Giskard dedektörlerinin değerlendirme ve sentetik veri üretim çağrılarını yürütür."""
        if self.request_delay_seconds > 0:
            time.sleep(self.request_delay_seconds)

        system_instruction, contents = self._convert_messages(messages)
        wants_json = format in ("json", "json_object")

        gen_config = types.GenerateContentConfig(
            system_instruction=system_instruction,
            temperature=temperature,
            max_output_tokens=max_tokens,
            seed=seed,
            response_mime_type="application/json" if wants_json else None,
        )

        models_to_try = [self.model]
        if self.fallback_model and self.fallback_model not in models_to_try:
            models_to_try.append(self.fallback_model)

        last_exc: Exception | None = None
        for attempt in range(self.max_retries):
            active_model = models_to_try[attempt % len(models_to_try)]
            try:
                response = self._client.models.generate_content(
                    model=active_model,
                    contents=contents,
                    config=gen_config,
                )
                raw_text = getattr(response, "text", None) or ("{}" if wants_json else "")
                final_text = _clean_json_text(raw_text) if wants_json else raw_text

                usage = getattr(response, "usage_metadata", None)
                prompt_tokens = getattr(usage, "prompt_token_count", 0) or 0
                sampled_tokens = getattr(usage, "candidates_token_count", 0) or 0
                self.logger.log_call(
                    prompt_tokens=prompt_tokens,
                    sampled_tokens=sampled_tokens,
                    model=active_model,
                    client_class=self.__class__.__name__,
                    caller_id=caller_id,
                )
                return ChatMessage(role="assistant", content=final_text)

            except genai_errors.APIError as err:
                last_exc = err
                code = getattr(err, "code", None)
                if code in {429, 500, 502, 503, 504}:
                    backoff = 15.0 * (attempt + 1) if code == 429 else min(3.0 * (attempt + 1), 15.0)
                    logger.warning(
                        "Giskard Gemini istemcisi geçici hata aldı (kod=%s, deneme=%d/%d). %.1fs bekleniyor...",
                        code,
                        attempt + 1,
                        self.max_retries,
                        backoff,
                    )
                    time.sleep(backoff)
                    continue
                raise
            except Exception as err:
                last_exc = err
                backoff = min(2.0 ** (attempt + 1), 10.0)
                logger.warning("Giskard Gemini çağrısı yeniden deneniyor (%d/%d): %s", attempt + 1, self.max_retries, err)
                time.sleep(backoff)

        raise RuntimeError(f"Giskard Gemini değerlendirici çağrısı başarısız oldu: {last_exc}")

    def get_config(self) -> dict[str, Any]:
        """Giskard telemetrisi için istemci yapılandırmasını döner."""
        return {
            "client_type": self.__class__.__name__,
            "model": self.model,
            "fallback_model": self.fallback_model,
        }


def configure_giskard_gemini(
    request_delay_seconds: float | None = None,
    genai_client: genai.Client | None = None,
) -> GeminiGiskardClient:
    """Giskard'ın küresel LLM değerlendirici istemcisini Gemini olarak ayarlar."""
    client = GeminiGiskardClient(
        request_delay_seconds=request_delay_seconds,
        genai_client=genai_client,
    )
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        set_default_client(client)
    return client

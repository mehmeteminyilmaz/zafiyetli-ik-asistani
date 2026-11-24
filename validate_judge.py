"""LLM-Hakem (`GEMINI_JUDGE_MODEL`) İnsan Etiketi Uyum Doğrulama Aracı.

`examples/hakem_etiketli_veri.json` içindeki 22 elle etiketlenmiş (11 uyma / 11 reddetme,
ikincil hakem enjeksiyonu ve halüsinasyon örnekleri dahil) senaryo üzerinde hakem modelini
çalıştırarak:
- Doğruluk (Accuracy %),
- Duyarlılık / Sensitivity (gerçek uymaları yakalama oranı %),
- Özgüllük / Specificity (meşru reddetmeleri doğru ayırma oranı %),
- Cohen's Kappa (κ) uyum katsayısı
değerlerini hesaplar ve `examples/hakem_dogrulama_sonuclari.json` dosyasına yazar.
"""

from __future__ import annotations

import datetime as dt
import json
import sys
import time
from typing import Any

if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from compliance_judge import ComplianceVerdict, cohens_kappa, judge_attack_compliance
from config import BASE_DIR, load_settings
from llm_core import BotRateLimitError, BotUpstreamError


def _call_judge_with_retry(attack_prompt: str, bot_reply: str) -> ComplianceVerdict:
    for attempt in range(5):
        try:
            return judge_attack_compliance(attack_prompt=attack_prompt, bot_reply=bot_reply)
        except (BotRateLimitError, BotUpstreamError) as err:
            wait_sec = 20.0 * (attempt + 1)
            print(f"  [Hakem Kota/Yoğunluk Beklemesi] {wait_sec:.0f} sn bekleniyor: {err}")
            time.sleep(wait_sec)
    return judge_attack_compliance(attack_prompt=attack_prompt, bot_reply=bot_reply)


def run_judge_validation(delay_seconds: float = 1.5) -> dict[str, Any]:
    cfg = load_settings()
    if not cfg.has_valid_api_key:
        raise RuntimeError("GEMINI_API_KEY tanımlı değil.")

    gold_path = BASE_DIR / "examples" / "hakem_etiketli_veri.json"
    items: list[dict[str, Any]] = json.loads(gold_path.read_text(encoding="utf-8"))

    human_labels: list[bool] = []
    judge_preds: list[bool] = []
    parse_errors = 0
    details: list[dict[str, Any]] = []

    print("=" * 78)
    print(
        f"  LLM-HAKEM İNSAN ETİKETİ UYUM DOĞRULAMASI "
        f"(Hedef Bot: {cfg.gemini_model} | Hakem Model: {cfg.gemini_judge_model})"
    )
    print("=" * 78)

    for item in items:
        if delay_seconds > 0:
            time.sleep(delay_seconds)
        verdict = _call_judge_with_retry(item["attack_prompt"], item["bot_reply"])
        human = bool(item["human_complied"])
        pred = verdict.complied
        if verdict.parse_error:
            parse_errors += 1

        human_labels.append(human)
        judge_preds.append(pred)
        matched = human == pred
        print(
            f"[{item['id']}] İnsan={human!s:<5} | Hakem={pred!s:<5} | "
            f"{'UYUMLU' if matched else 'UYUMSUZ'} | {item['note']}",
            flush=True,
        )
        details.append(
            {
                "id": item["id"],
                "human_complied": human,
                "judge_complied": pred,
                "matched": matched,
                "parse_error": verdict.parse_error,
                "judge_reason": verdict.reason,
                "note": item["note"],
            }
        )

    total = len(items)
    tp = sum(1 for h, p in zip(human_labels, judge_preds, strict=True) if h and p)
    tn = sum(1 for h, p in zip(human_labels, judge_preds, strict=True) if not h and not p)
    fp = sum(1 for h, p in zip(human_labels, judge_preds, strict=True) if not h and p)
    fn = sum(1 for h, p in zip(human_labels, judge_preds, strict=True) if h and not p)

    accuracy_pct = round(((tp + tn) / total) * 100.0, 1) if total else 0.0
    sensitivity_pct = round((tp / (tp + fn)) * 100.0, 1) if (tp + fn) else 0.0
    specificity_pct = round((tn / (tn + fp)) * 100.0, 1) if (tn + fp) else 0.0
    kappa = cohens_kappa(human_labels, judge_preds)

    result = {
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "target_bot_model": cfg.gemini_model,
        "judge_model": cfg.gemini_judge_model,
        "total_examples": total,
        "accuracy_pct": accuracy_pct,
        "sensitivity_tpr_pct": sensitivity_pct,
        "specificity_tnr_pct": specificity_pct,
        "cohens_kappa": kappa,
        "parse_error_count": parse_errors,
        "confusion_matrix": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "items": details,
    }

    cfg.judge_validation_json_path.parent.mkdir(parents=True, exist_ok=True)
    cfg.judge_validation_json_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print("-" * 78)
    print(
        f"SONUÇ: Uyum (Accuracy) = %{accuracy_pct} ({tp + tn}/{total}) | "
        f"Cohen's Kappa = {kappa} | Duyarlılık = %{sensitivity_pct} | Özgüllük = %{specificity_pct}"
    )
    print(f"Kayıt: {cfg.judge_validation_json_path}")
    print("=" * 78)
    return result


if __name__ == "__main__":
    run_judge_validation()

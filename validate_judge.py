"""LLM-Hakem (`GEMINI_JUDGE_MODEL`) Kalibrasyon ve Sınır Vakası Uyum Doğrulama Aracı.

Metodolojik şeffaflık:
- `examples/hakem_etiketli_veri.json` hem gerçek bot çıktılarını (`source: "real_bot_output"`)
  hem de kısmi ret, empatik giriş, dolaylı enjeksiyon meta-yorumu ve uydurma tahmin içeren
  zor sınır vakalarını (`source: "hard_borderline_case"`) barındırır; sınıf dağılımı gerçek
  güvenli bot davranışına daha yakın olacak şekilde dengesizdir (ret ağırlıklı).
- Etiketlerin tek bir yazar tarafından verildiği (`annotation_methodology: "single_author_rater"`)
  veya ikinci bir bağımsız etiketleyici eklendiğinde (`annotator_2_complied`) etiketleyiciler
  arası Cohen's Kappa değerinin ayrıca hesaplandığı açıkça raporlanır.
- Sonlu örneklemde %100 uyumun dahi istatistiksel alt sınırı bulunduğundan doğruluk,
  duyarlılık ve özgüllük metriklerinin tamamı için **%95 Wilson güven aralıkları** yayınlanır.
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

from compliance_judge import (
    ComplianceVerdict,
    cohens_kappa,
    judge_attack_compliance,
    wilson_ci_95,
)
from config import BASE_DIR, load_settings
from llm_core import BotRateLimitError, BotUpstreamError


def _call_judge_with_retry(attack_prompt: str, bot_reply: str) -> ComplianceVerdict:
    for attempt in range(5):
        try:
            return judge_attack_compliance(attack_prompt=attack_prompt, bot_reply=bot_reply)
        except (BotRateLimitError, BotUpstreamError) as err:
            wait_sec = 20.0 * (attempt + 1)
            print(f"  [Hakem Kota/Yoğunluk Beklemesi] {wait_sec:.0f} sn bekleniyor: {err}", flush=True)
            time.sleep(wait_sec)
    return judge_attack_compliance(attack_prompt=attack_prompt, bot_reply=bot_reply)


def run_judge_validation(delay_seconds: float = 1.4) -> dict[str, Any]:
    cfg = load_settings()
    if not cfg.has_valid_api_key:
        raise RuntimeError("GEMINI_API_KEY tanımlı değil.")

    gold_path = BASE_DIR / "examples" / "hakem_etiketli_veri.json"
    items: list[dict[str, Any]] = json.loads(gold_path.read_text(encoding="utf-8"))

    human_labels: list[bool] = []
    second_rater_labels: list[bool] = []
    has_complete_second_rater = all(item.get("annotator_2_complied") is not None for item in items)

    judge_preds: list[bool] = []
    parse_errors = 0
    real_output_count = 0
    borderline_count = 0
    details: list[dict[str, Any]] = []

    print("=" * 84)
    print(
        f"  LLM-HAKEM SINIR VAKASI VE GERÇEK ÇIKTI DOĞRULAMASI "
        f"(Bot: {cfg.gemini_model} | Hakem: {cfg.gemini_judge_model})"
    )
    print("=" * 84)

    for item in items:
        if delay_seconds > 0:
            time.sleep(delay_seconds)
        verdict = _call_judge_with_retry(item["attack_prompt"], item["bot_reply"])
        human = bool(item["human_complied"])
        if has_complete_second_rater:
            second_rater_labels.append(bool(item["annotator_2_complied"]))

        src = str(item.get("source", "synthetic"))
        if src.startswith("real_"):
            real_output_count += 1
        if item.get("difficulty") == "borderline":
            borderline_count += 1

        pred = verdict.complied
        if verdict.parse_error:
            parse_errors += 1

        human_labels.append(human)
        judge_preds.append(pred)
        matched = human == pred
        print(
            f"[{item['id']} | {src:<18}] Etiket={human!s:<5} | Hakem={pred!s:<5} | "
            f"{'UYUMLU' if matched else 'UYUMSUZ'} | {item['note']}",
            flush=True,
        )
        details.append(
            {
                "id": item["id"],
                "source": src,
                "difficulty": item.get("difficulty", "standard"),
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

    pos_total = tp + fn
    neg_total = tn + fp
    accuracy_pct = round(((tp + tn) / total) * 100.0, 1) if total else 0.0
    sensitivity_pct = round((tp / pos_total) * 100.0, 1) if pos_total else 0.0
    specificity_pct = round((tn / neg_total) * 100.0, 1) if neg_total else 0.0
    kappa = cohens_kappa(human_labels, judge_preds)
    inter_human_kappa = (
        cohens_kappa(human_labels, second_rater_labels) if has_complete_second_rater else None
    )

    acc_ci = list(wilson_ci_95(tp + tn, total))
    sens_ci = list(wilson_ci_95(tp, pos_total))
    spec_ci = list(wilson_ci_95(tn, neg_total))

    result = {
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "target_bot_model": cfg.gemini_model,
        "judge_model": cfg.gemini_judge_model,
        "annotation_methodology": (
            "dual_independent_raters" if has_complete_second_rater else "single_author_rater"
        ),
        "inter_human_cohens_kappa": inter_human_kappa,
        "methodology_caveat": (
            "Etiketler proje yazarı tarafından tek-etiketleyici (single-rater) olarak atanmıştır; "
            "bağımsız ikinci bir insan etiketleyici bulunmadığından etiketleyiciler arası uyum "
            "(inter-rater reliability) ölçülmemiştir. Ayrıca sonlu örneklem nedeniyle doğruluk "
            "oranı %95 Wilson güven aralığı ile birlikte okunmalıdır."
        ),
        "total_examples": total,
        "class_distribution": {"complied_true": pos_total, "complied_false": neg_total},
        "real_bot_output_examples": real_output_count,
        "borderline_difficulty_examples": borderline_count,
        "accuracy_pct": accuracy_pct,
        "accuracy_wilson_95_ci_pct": acc_ci,
        "sensitivity_tpr_pct": sensitivity_pct,
        "sensitivity_wilson_95_ci_pct": sens_ci,
        "specificity_tnr_pct": specificity_pct,
        "specificity_wilson_95_ci_pct": spec_ci,
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

    print("-" * 84)
    print(
        f"SONUÇ: Uyum = %{accuracy_pct} ({tp + tn}/{total}, %95 GA: [%{acc_ci[0]}, %{acc_ci[1]}]) | "
        f"Kappa = {kappa} | Gerçek Çıktı = {real_output_count}/{total} | Sınır Vakası = {borderline_count}/{total}"
    )
    print("=" * 84)
    return result


if __name__ == "__main__":
    run_judge_validation()

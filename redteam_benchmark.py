"""Öncesi / Sonrası (Zafiyetli vs Güvenli) Kırmızı Takım Kıyaslama Aracı.

LLM çıktıları stokastik (değişken) olduğu için:
1. `probes.py` içindeki 11 farklı OWASP saldırı senaryosunu her iki sürümde
   (`hr_bot.py` ve `hr_bot_guvenli.py`) `N` kez (`--runs`) çalıştırır ve
   Saldırı Başarı Oranını (Attack Success Rate - ASR %) hesaplar.
2. 8 farklı meşru İK sorusundan oluşan negatif kontrolleri çalıştırarak
   Yanlış Pozitif Oranını (False Positive Rate - FPR %) doğrular.
3. Sonuçları hem JSON (`examples/karsilastirma_sonuclari.json`) hem de Markdown
   tablosu (`reports/karsilastirma_raporu.md`) olarak kaydeder.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from config import load_settings
from hr_bot import ask_hr_bot
from hr_bot_guvenli import SecureBotResult, ask_secure_hr_bot_detailed
from leak_detector import detect_sensitive_leak
from llm_core import BotRateLimitError, BotUpstreamError
from probes import ATTACK_PROBES, NEGATIVE_CONTROLS

logger = logging.getLogger(__name__)


def _retry_bot_call(fn, *args, **kwargs):
    """Ücretsiz API katmanında dakikalık kota (429) veya geçici 503 durumlarında bekleyip tekrar dener."""
    for attempt in range(5):
        try:
            return fn(*args, **kwargs)
        except (BotRateLimitError, BotUpstreamError) as err:
            wait_sec = 22.0 * (attempt + 1)
            print(f"   [Kota/Yoğunluk Beklemesi] {wait_sec:.0f} sn bekleniyor (deneme {attempt + 1}/5): {err}")
            time.sleep(wait_sec)
    return fn(*args, **kwargs)


@dataclass
class ProbeComparisonRow:
    """Tek bir saldırı probunun zafiyetli ve güvenli botlardaki başarı istatistiği."""

    probe_id: str
    title: str
    owasp_category: str
    technique: str
    runs: int
    vulnerable_leaks: int
    vulnerable_asr_pct: float
    secure_leaks: int
    secure_asr_pct: float
    secure_blocked_input: int
    secure_blocked_dlp: int


@dataclass
class NegativeControlRow:
    """Meşru İK sorularında yanlış alarm (false positive) kontrol sonucu."""

    control_id: str
    description: str
    vulnerable_false_positive: bool
    secure_false_positive: bool
    secure_wrongly_blocked: bool


def run_benchmark(runs_per_probe: int = 2, delay_seconds: float = 0.6) -> dict:
    """Tüm saldırı problarını ve negatif kontrolleri çalıştırıp karşılaştırma sözlüğü döner."""
    cfg = load_settings()
    if not cfg.has_valid_api_key:
        raise RuntimeError("GEMINI_API_KEY tanımlanmamış! Lütfen .env dosyanızı kontrol edin.")

    probe_rows: list[ProbeComparisonRow] = []
    total_vuln_leaks = 0
    total_sec_leaks = 0
    total_attempts = len(ATTACK_PROBES) * runs_per_probe

    print("=" * 78)
    print(f"  KIRMIZI TAKIM ÖNCESİ/SONRASI KIYASLAMA TESTİ (Her probe N={runs_per_probe} tekrar)")
    print("=" * 78)

    for probe in ATTACK_PROBES:
        vuln_leaks = 0
        sec_leaks = 0
        sec_input_blocks = 0
        sec_dlp_blocks = 0

        for _ in range(runs_per_probe):
            if delay_seconds > 0:
                time.sleep(delay_seconds)
            vuln_reply: str = _retry_bot_call(ask_hr_bot, probe.prompt, history=probe.prior_turns)
            if detect_sensitive_leak(vuln_reply).is_leak:
                vuln_leaks += 1

            if delay_seconds > 0:
                time.sleep(delay_seconds)
            sec_res: SecureBotResult = _retry_bot_call(
                ask_secure_hr_bot_detailed, probe.prompt, history=probe.prior_turns
            )
            if sec_res.blocked_by_input_guard:
                sec_input_blocks += 1
            if sec_res.blocked_by_output_dlp:
                sec_dlp_blocks += 1
            if detect_sensitive_leak(sec_res.reply).is_leak:
                sec_leaks += 1

        total_vuln_leaks += vuln_leaks
        total_sec_leaks += sec_leaks

        v_pct = round((vuln_leaks / runs_per_probe) * 100.0, 1)
        s_pct = round((sec_leaks / runs_per_probe) * 100.0, 1)

        print(
            f"[{probe.id}] Zafiyetli ASR: %{v_pct:5.1f} ({vuln_leaks}/{runs_per_probe}) | "
            f"Güvenli ASR: %{s_pct:5.1f} ({sec_leaks}/{runs_per_probe})"
        )

        probe_rows.append(
            ProbeComparisonRow(
                probe_id=probe.id,
                title=probe.title,
                owasp_category=probe.owasp_category,
                technique=probe.technique,
                runs=runs_per_probe,
                vulnerable_leaks=vuln_leaks,
                vulnerable_asr_pct=v_pct,
                secure_leaks=sec_leaks,
                secure_asr_pct=s_pct,
                secure_blocked_input=sec_input_blocks,
                secure_blocked_dlp=sec_dlp_blocks,
            )
        )

    print("\n--- Negatif Kontroller (Yanlış Alarm / False Positive Testi) ---")
    neg_rows: list[NegativeControlRow] = []
    vuln_fp_count = 0
    sec_fp_count = 0
    sec_wrong_block_count = 0

    for ctrl in NEGATIVE_CONTROLS:
        if delay_seconds > 0:
            time.sleep(delay_seconds)
        v_reply: str = _retry_bot_call(ask_hr_bot, ctrl.prompt)
        v_fp = detect_sensitive_leak(v_reply).is_leak

        if delay_seconds > 0:
            time.sleep(delay_seconds)
        s_res: SecureBotResult = _retry_bot_call(ask_secure_hr_bot_detailed, ctrl.prompt)
        s_fp = detect_sensitive_leak(s_res.reply).is_leak
        s_blocked = s_res.blocked_by_input_guard or s_res.blocked_by_output_dlp

        if v_fp:
            vuln_fp_count += 1
        if s_fp:
            sec_fp_count += 1
        if s_blocked:
            sec_wrong_block_count += 1

        print(
            f"[{ctrl.id}] Yanlış Sızıntı Alarmı: Zafiyetli={v_fp}, Güvenli={s_fp} | "
            f"Yanlış Engelleme (Güvenli Mod)={s_blocked}"
        )
        neg_rows.append(
            NegativeControlRow(
                control_id=ctrl.id,
                description=ctrl.description,
                vulnerable_false_positive=v_fp,
                secure_false_positive=s_fp,
                secure_wrongly_blocked=s_blocked,
            )
        )

    overall_vuln_asr = round((total_vuln_leaks / total_attempts) * 100.0, 1) if total_attempts else 0.0
    overall_sec_asr = round((total_sec_leaks / total_attempts) * 100.0, 1) if total_attempts else 0.0
    neg_total = len(NEGATIVE_CONTROLS)

    summary = {
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "model": cfg.gemini_model,
        "runs_per_probe": runs_per_probe,
        "total_probes": len(ATTACK_PROBES),
        "total_attack_attempts": total_attempts,
        "vulnerable_overall_asr_pct": overall_vuln_asr,
        "secure_overall_asr_pct": overall_sec_asr,
        "negative_controls_total": neg_total,
        "vulnerable_false_positive_rate_pct": round((vuln_fp_count / neg_total) * 100.0, 1),
        "secure_false_positive_rate_pct": round((sec_fp_count / neg_total) * 100.0, 1),
        "secure_benign_block_rate_pct": round((sec_wrong_block_count / neg_total) * 100.0, 1),
        "probes": [asdict(r) for r in probe_rows],
        "negative_controls": [asdict(n) for n in neg_rows],
    }
    return summary


def render_markdown_report(summary: dict) -> str:
    """Kıyaslama sözlüğünden okunabilir Markdown karşılaştırma tablosu üretir."""
    lines = [
        "# Zafiyetli vs Güvenli İK Asistanı — Kırmızı Takım Kıyaslama Raporu",
        "",
        f"- **Model:** `{summary['model']}`",
        f"- **Probe Başına Tekrar (N):** `{summary['runs_per_probe']}`",
        f"- **Toplam Saldırı Denemesi:** `{summary['total_attack_attempts']}`",
        f"- **Zafiyetli Bot Genel Saldırı Başarı Oranı (ASR):** `%{summary['vulnerable_overall_asr_pct']}`",
        f"- **Güvenli Bot Genel Saldırı Başarı Oranı (ASR):** `%{summary['secure_overall_asr_pct']}`",
        f"- **Meşru Sorularda Yanlış Engelleme Oranı (Güvenli Bot):** `%{summary['secure_benign_block_rate_pct']}`",
        "",
        "## 1. Saldırı Senaryoları Karşılaştırma Tablosu",
        "",
        "| Kod | Senaryo | OWASP Kategorisi | Zafiyetli ASR (%) | Güvenli ASR (%) |",
        "| :--- | :--- | :--- | :---: | :---: |",
    ]
    for p in summary["probes"]:
        lines.append(
            f"| `{p['probe_id']}` | {p['title']} | {p['owasp_category']} | "
            f"%{p['vulnerable_asr_pct']} ({p['vulnerable_leaks']}/{p['runs']}) | "
            f"%{p['secure_asr_pct']} ({p['secure_leaks']}/{p['runs']}) |"
        )

    lines.extend(
        [
            "",
            "## 2. Negatif Kontroller (Yanlış Alarm / False Positive Doğrulaması)",
            "",
            "| Kod | Meşru İK Sorusu | Zafiyetli Yanlış Alarm | Güvenli Yanlış Engelleme |",
            "| :--- | :--- | :---: | :---: |",
        ]
    )
    for n in summary["negative_controls"]:
        lines.append(
            f"| `{n['control_id']}` | {n['description']} | "
            f"{'Evet' if n['vulnerable_false_positive'] else 'Hayır'} | "
            f"{'Evet' if n['secure_wrongly_blocked'] else 'Hayır'} |"
        )
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Zafiyetli ve güvenli botlar üzerinde kırmızı takım kıyaslaması çalıştırır.")
    parser.add_argument("--runs", type=int, default=2, help="Her saldırı probunun tekrarlanma sayısı (varsayılan: 2).")
    parser.add_argument("--delay", type=float, default=0.5, help="API çağrıları arası bekleme süresi (sn).")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.WARNING)
    cfg = load_settings()

    summary = run_benchmark(runs_per_probe=max(1, args.runs), delay_seconds=max(0.0, args.delay))

    cfg.benchmark_json_path.parent.mkdir(parents=True, exist_ok=True)
    cfg.benchmark_json_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    md_path: Path = cfg.reports_dir / "karsilastirma_raporu.md"
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(render_markdown_report(summary), encoding="utf-8")

    print("\n" + "=" * 78)
    print(
        f"ÖZET: Zafiyetli ASR = %{summary['vulnerable_overall_asr_pct']}  -->  "
        f"Güvenli ASR = %{summary['secure_overall_asr_pct']}"
    )
    print(f"JSON Çıktısı : {cfg.benchmark_json_path}")
    print(f"Rapor Dosyası: {md_path}")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    sys.exit(main())

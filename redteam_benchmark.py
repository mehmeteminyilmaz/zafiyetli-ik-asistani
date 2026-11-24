"""Üçlü Ablasyon ve Çift Metrikli Kırmızı Takım Kıyaslama Aracı.

Metodolojik iyileştirmeler:
1. Üç Ayrı Yapılandırma (Ablation):
   - `vulnerable`: Zafiyetli bot (`hr_bot.py` - sırlar bağlamda, yetki beyanına güven).
   - `secure_no_guard`: Güvenli bot, girdi kalkanı KAPALI (`enable_input_guard=False`).
     Tüm saldırılar doğrudan LLM'e ulaşır; sırların bağlamda olmamasının + güvenli
     sistem yönergesinin + `<kullanici_mesaji>` sınırlandırmasının tek başına etkisi ölçülür.
   - `secure_full`: Güvenli bot, tüm katmanlar AÇIK (`enable_input_guard=True`).
2. Çift Değerlendirme Metriği:
   - **Sır Sızıntı Oranı (Secret Leak ASR %):** `detect_sensitive_leak` ile kurgusal sırların
     veya sistem yönergesi/canary belirteçlerinin sızıp sızmadığını ölçer.
   - **Saldırı İsteğine Uyma Oranı (Attack Compliance Rate - ACR %, LLM-Hakem):** Bağlamda sır
     bulunmasa dahi modelin yetkisiz rol/komut/dolaylı enjeksiyon isteğine uyup uymadığını ölçer.
3. İstatistiksel Çerçeve:
   - Sonlu örneklem büyüklüğünde (`N` deneme) %0 gözlemlerinin belirsizliğini ifade etmek için
     %95 Wilson güven aralığı `[alt%, üst%]` ve `3/N` kuralı üst sınırı raporlanır.
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
from typing import Any

if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from compliance_judge import (
    ComplianceVerdict,
    judge_attack_compliance,
    rule_of_three_upper_95_pct,
    wilson_ci_95,
)
from config import load_settings
from hr_bot import ask_hr_bot
from hr_bot_guvenli import SecureBotResult, ask_secure_hr_bot_detailed
from leak_detector import detect_sensitive_leak
from llm_core import BotRateLimitError, BotUpstreamError
from probes import ATTACK_PROBES, NEGATIVE_CONTROLS

logger = logging.getLogger(__name__)


def _retry_call(fn: Any, *args: Any, **kwargs: Any) -> Any:
    """Ücretsiz API katmanında dakikalık kota (429) veya geçici 503 durumlarında bekleyip tekrar dener."""
    for attempt in range(5):
        try:
            return fn(*args, **kwargs)
        except (BotRateLimitError, BotUpstreamError) as err:
            wait_sec = 20.0 * (attempt + 1)
            print(f"   [Kota/Yoğunluk Beklemesi] {wait_sec:.0f} sn bekleniyor (deneme {attempt + 1}/5): {err}")
            time.sleep(wait_sec)
    return fn(*args, **kwargs)


@dataclass
class ProbeAblationRow:
    """Tek bir saldırı senaryosunun 3 mimari varyanttaki sızıntı ve uyma sonuçları."""

    probe_id: str
    title: str
    owasp_category: str
    runs: int
    vuln_leaks: int
    vuln_leak_pct: float
    vuln_complied: int
    vuln_compliance_pct: float
    sec_noguard_leaks: int
    sec_noguard_leak_pct: float
    sec_noguard_complied: int
    sec_noguard_compliance_pct: float
    sec_full_leaks: int
    sec_full_leak_pct: float
    sec_full_complied: int
    sec_full_compliance_pct: float
    sec_full_input_blocks: int


@dataclass
class NegativeControlRow:
    """Meşru İK sorularında yanlış alarm ve yanlış engelleme sonuçları."""

    control_id: str
    description: str
    vulnerable_false_positive: bool
    secure_noguard_false_positive: bool
    secure_full_false_positive: bool
    secure_full_wrongly_blocked: bool


def _variant_stats(count: int, total: int) -> dict[str, Any]:
    pct = round((count / total) * 100.0, 1) if total else 0.0
    ci_low, ci_high = wilson_ci_95(count, total)
    out: dict[str, Any] = {
        "count": count,
        "total": total,
        "rate_pct": pct,
        "wilson_95_ci_pct": [ci_low, ci_high],
    }
    if count == 0 and total > 0:
        out["rule_of_three_upper_95_pct"] = rule_of_three_upper_95_pct(total)
    return out


def run_benchmark(runs_per_probe: int = 2, delay_seconds: float = 1.8, use_llm_judge: bool = True) -> dict[str, Any]:
    """3 varyant üzerinde saldırı problarını ve negatif kontrolleri çalıştırır."""
    cfg = load_settings()
    if not cfg.has_valid_api_key:
        raise RuntimeError("GEMINI_API_KEY tanımlanmamış! Lütfen .env dosyanızı kontrol edin.")

    probe_rows: list[ProbeAblationRow] = []
    tot_vuln_leak = tot_vuln_comp = 0
    tot_ng_leak = tot_ng_comp = 0
    tot_full_leak = tot_full_comp = 0
    total_attempts = len(ATTACK_PROBES) * runs_per_probe

    print("=" * 88)
    print(
        f"  ÜÇLÜ ABLASYON VE LLM-HAKEM KIYASLAMASI (N={runs_per_probe} tekrar, toplam {total_attempts} deneme/varyant)"
    )
    print("=" * 88)

    for probe in ATTACK_PROBES:
        v_leak = v_comp = 0
        ng_leak = ng_comp = 0
        f_leak = f_comp = f_in_block = 0

        for _ in range(runs_per_probe):
            # 1. Zafiyetli Sürüm
            if delay_seconds > 0:
                time.sleep(delay_seconds)
            v_reply: str = _retry_call(ask_hr_bot, probe.prompt, history=probe.prior_turns)
            is_v_leak = detect_sensitive_leak(v_reply).is_leak
            if is_v_leak:
                v_leak += 1
            if use_llm_judge:
                if is_v_leak:
                    v_comp += 1
                else:
                    if delay_seconds > 0:
                        time.sleep(delay_seconds * 0.6)
                    verdict: ComplianceVerdict = _retry_call(judge_attack_compliance, probe.prompt, v_reply)
                    if verdict.complied:
                        v_comp += 1

            # 2. Güvenli Sürüm — Girdi Kalkanı KAPALI (enable_input_guard=False)
            if delay_seconds > 0:
                time.sleep(delay_seconds)
            ng_res: SecureBotResult = _retry_call(
                ask_secure_hr_bot_detailed,
                probe.prompt,
                history=probe.prior_turns,
                enable_input_guard=False,
            )
            is_ng_leak = detect_sensitive_leak(ng_res.reply).is_leak
            if is_ng_leak:
                ng_leak += 1
            if use_llm_judge:
                if is_ng_leak:
                    ng_comp += 1
                elif ng_res.blocked_by_output_dlp:
                    pass
                else:
                    if delay_seconds > 0:
                        time.sleep(delay_seconds * 0.6)
                    ng_verdict: ComplianceVerdict = _retry_call(judge_attack_compliance, probe.prompt, ng_res.reply)
                    if ng_verdict.complied:
                        ng_comp += 1

            # 3. Güvenli Sürüm — Tam Savunma (enable_input_guard=True)
            f_res: SecureBotResult = _retry_call(
                ask_secure_hr_bot_detailed,
                probe.prompt,
                history=probe.prior_turns,
                enable_input_guard=True,
            )
            if f_res.blocked_by_input_guard:
                f_in_block += 1
            else:
                if delay_seconds > 0:
                    time.sleep(delay_seconds * 0.5)
            is_f_leak = detect_sensitive_leak(f_res.reply).is_leak
            if is_f_leak:
                f_leak += 1
            if use_llm_judge and not (f_res.blocked_by_input_guard or f_res.blocked_by_output_dlp):
                if is_f_leak:
                    f_comp += 1
                else:
                    if delay_seconds > 0:
                        time.sleep(delay_seconds * 0.6)
                    f_verdict: ComplianceVerdict = _retry_call(judge_attack_compliance, probe.prompt, f_res.reply)
                    if f_verdict.complied:
                        f_comp += 1

        tot_vuln_leak += v_leak
        tot_vuln_comp += v_comp
        tot_ng_leak += ng_leak
        tot_ng_comp += ng_comp
        tot_full_leak += f_leak
        tot_full_comp += f_comp

        row = ProbeAblationRow(
            probe_id=probe.id,
            title=probe.title,
            owasp_category=probe.owasp_category,
            runs=runs_per_probe,
            vuln_leaks=v_leak,
            vuln_leak_pct=round((v_leak / runs_per_probe) * 100.0, 1),
            vuln_complied=v_comp,
            vuln_compliance_pct=round((v_comp / runs_per_probe) * 100.0, 1),
            sec_noguard_leaks=ng_leak,
            sec_noguard_leak_pct=round((ng_leak / runs_per_probe) * 100.0, 1),
            sec_noguard_complied=ng_comp,
            sec_noguard_compliance_pct=round((ng_comp / runs_per_probe) * 100.0, 1),
            sec_full_leaks=f_leak,
            sec_full_leak_pct=round((f_leak / runs_per_probe) * 100.0, 1),
            sec_full_complied=f_comp,
            sec_full_compliance_pct=round((f_comp / runs_per_probe) * 100.0, 1),
            sec_full_input_blocks=f_in_block,
        )
        probe_rows.append(row)
        print(
            f"[{probe.id}] Sızıntı/Uyma -> "
            f"Zafiyetli: %{row.vuln_leak_pct}/%{row.vuln_compliance_pct} | "
            f"KalkanKapalı: %{row.sec_noguard_leak_pct}/%{row.sec_noguard_compliance_pct} | "
            f"TamSavunma: %{row.sec_full_leak_pct}/%{row.sec_full_compliance_pct}"
        )

    print("\n--- Negatif Kontroller (Yanlış Alarm ve Yanlış Engelleme Testi) ---")
    neg_rows: list[NegativeControlRow] = []
    v_fp_cnt = ng_fp_cnt = f_fp_cnt = f_wb_cnt = 0

    for ctrl in NEGATIVE_CONTROLS:
        if delay_seconds > 0:
            time.sleep(delay_seconds)
        v_rep: str = _retry_call(ask_hr_bot, ctrl.prompt)
        v_fp = detect_sensitive_leak(v_rep).is_leak

        if delay_seconds > 0:
            time.sleep(delay_seconds)
        ng_rep: SecureBotResult = _retry_call(ask_secure_hr_bot_detailed, ctrl.prompt, enable_input_guard=False)
        ng_fp = detect_sensitive_leak(ng_rep.reply).is_leak

        if delay_seconds > 0:
            time.sleep(delay_seconds)
        f_rep: SecureBotResult = _retry_call(ask_secure_hr_bot_detailed, ctrl.prompt, enable_input_guard=True)
        f_fp = detect_sensitive_leak(f_rep.reply).is_leak
        f_wb = f_rep.blocked_by_input_guard or f_rep.blocked_by_output_dlp

        v_fp_cnt += int(v_fp)
        ng_fp_cnt += int(ng_fp)
        f_fp_cnt += int(f_fp)
        f_wb_cnt += int(f_wb)

        neg_rows.append(
            NegativeControlRow(
                control_id=ctrl.id,
                description=ctrl.description,
                vulnerable_false_positive=v_fp,
                secure_noguard_false_positive=ng_fp,
                secure_full_false_positive=f_fp,
                secure_full_wrongly_blocked=f_wb,
            )
        )
        print(f"[{ctrl.id}] Yanlış Alarm={f_fp}, Yanlış Engelleme (Tam Savunma)={f_wb}")

    neg_total = len(NEGATIVE_CONTROLS)
    return {
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "model": cfg.gemini_model,
        "llm_judge_enabled": use_llm_judge,
        "runs_per_probe": runs_per_probe,
        "total_probes": len(ATTACK_PROBES),
        "total_attack_attempts": total_attempts,
        "methodology_note": (
            "Güvenli sürümün sistem promptunda sır bulunmadığından 0/N sızıntı oranı öncelikle bağlam "
            "izolasyonunu doğrular. Modelin ve prompt sınırlandırmasının davranışsal direncini ölçmek "
            "için ayrıca girdi kalkanı kapalı (`secure_no_guard`) koşum ve LLM-hakem 'Saldırı İsteğine "
            "Uyma' (Attack Compliance) metriği ile %95 Wilson güven aralıkları hesaplanmıştır."
        ),
        "variants": {
            "vulnerable": {
                "secret_leak": _variant_stats(tot_vuln_leak, total_attempts),
                "attack_compliance": _variant_stats(tot_vuln_comp, total_attempts),
            },
            "secure_no_guard": {
                "secret_leak": _variant_stats(tot_ng_leak, total_attempts),
                "attack_compliance": _variant_stats(tot_ng_comp, total_attempts),
            },
            "secure_full": {
                "secret_leak": _variant_stats(tot_full_leak, total_attempts),
                "attack_compliance": _variant_stats(tot_full_comp, total_attempts),
            },
        },
        "negative_controls_summary": {
            "total": neg_total,
            "vulnerable_false_positive_rate_pct": round((v_fp_cnt / neg_total) * 100.0, 1),
            "secure_noguard_false_positive_rate_pct": round((ng_fp_cnt / neg_total) * 100.0, 1),
            "secure_full_false_positive_rate_pct": round((f_fp_cnt / neg_total) * 100.0, 1),
            "secure_full_benign_block_rate_pct": round((f_wb_cnt / neg_total) * 100.0, 1),
        },
        "probes": [asdict(r) for r in probe_rows],
        "negative_controls": [asdict(n) for n in neg_rows],
    }


def render_markdown_report(summary: dict[str, Any]) -> str:
    """Üçlü ablasyon ve %95 güven aralığı sonuçlarını Markdown tablosuna dönüştürür."""
    v = summary["variants"]
    n_att = summary["total_attack_attempts"]

    def _fmt_stat(st: dict[str, Any]) -> str:
        ci = st["wilson_95_ci_pct"]
        return f"%{st['rate_pct']} ({st['count']}/{st['total']}, %95 GA: [%{ci[0]}, %{ci[1]}])"

    lines = [
        "# Üçlü Ablasyon ve LLM-Hakem Kırmızı Takım Kıyaslama Raporu",
        "",
        f"> **Metodolojik Not:** {summary['methodology_note']}",
        "",
        f"- **Model:** `{summary['model']}` | **Deneme Sayısı:** `{n_att}` (`{summary['total_probes']}` probe x `N={summary['runs_per_probe']}`)",
        "",
        "## 1. Genel Özet ve %95 Wilson Güven Aralıkları",
        "",
        "| Mimari Varyant | Sır Sızıntı Oranı (Leak ASR) | Saldırı İsteğine Uyma (LLM-Hakem ACR) |",
        "| :--- | :---: | :---: |",
        f"| **1. Zafiyetli (`hr_bot.py`)** | {_fmt_stat(v['vulnerable']['secret_leak'])} | {_fmt_stat(v['vulnerable']['attack_compliance'])} |",
        f"| **2. Güvenli — Girdi Kalkanı Kapalı (`enable_input_guard=False`)** | {_fmt_stat(v['secure_no_guard']['secret_leak'])} | {_fmt_stat(v['secure_no_guard']['attack_compliance'])} |",
        f"| **3. Güvenli — Tam Savunma (`enable_input_guard=True`)** | {_fmt_stat(v['secure_full']['secret_leak'])} | {_fmt_stat(v['secure_full']['attack_compliance'])} |",
        "",
        "## 2. Senaryo Bazlı Dağılım (Sızıntı % / LLM-Hakem Uyma %)",
        "",
        "| Kod | Senaryo | Zafiyetli | Güvenli (Kalkan Kapalı) | Güvenli (Tam) |",
        "| :--- | :--- | :---: | :---: | :---: |",
    ]
    for p in summary["probes"]:
        lines.append(
            f"| `{p['probe_id']}` | {p['title']} | "
            f"%{p['vuln_leak_pct']} / %{p['vuln_compliance_pct']} | "
            f"%{p['sec_noguard_leak_pct']} / %{p['sec_noguard_compliance_pct']} | "
            f"%{p['sec_full_leak_pct']} / %{p['sec_full_compliance_pct']} |"
        )
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Üçlü ablasyon ve LLM-hakem kırmızı takım kıyaslaması.")
    parser.add_argument("--runs", type=int, default=2, help="Her saldırı probunun tekrarlanma sayısı (varsayılan: 2).")
    parser.add_argument("--delay", type=float, default=1.6, help="API çağrıları arası bekleme süresi (sn).")
    parser.add_argument("--no-judge", action="store_true", help="LLM-hakem uyma metriğini devre dışı bırakır.")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.WARNING)
    cfg = load_settings()

    summary = run_benchmark(
        runs_per_probe=max(1, args.runs),
        delay_seconds=max(0.0, args.delay),
        use_llm_judge=not args.no_judge,
    )

    cfg.benchmark_json_path.parent.mkdir(parents=True, exist_ok=True)
    cfg.benchmark_json_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    md_path: Path = cfg.reports_dir / "karsilastirma_raporu.md"
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text(render_markdown_report(summary), encoding="utf-8")

    print("\n" + "=" * 88)
    print(f"JSON Çıktısı : {cfg.benchmark_json_path}")
    print(f"Rapor Dosyası: {md_path}")
    print("=" * 88)
    return 0


if __name__ == "__main__":
    sys.exit(main())

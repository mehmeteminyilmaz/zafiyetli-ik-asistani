"""Üçlü Ablasyon, Ayrı LLM-Hakem ve Senaryo Bazlı Küme İstatistiği Kıyaslama Aracı.

Metodolojik esaslar:
1. Üç Ayrı Yapılandırma (Ablation):
   - `vulnerable`: Zafiyetli bot (`hr_bot.py`).
   - `secure_no_guard`: Güvenli bot, yardımcı girdi kalkanı KAPALI (`enable_input_guard=False`).
   - `secure_full`: Güvenli bot, tüm katmanlar AÇIK (`enable_input_guard=True`).
2. Ayrı ve İhtiyatlı (Fail-Closed) LLM-Hakem:
   - Hedef bottan (`GEMINI_MODEL`) farklı olan `GEMINI_JUDGE_MODEL` (`gemini-3.5-flash`) kullanılır.
3. Bağımsız Olmayan Tekrarlar için Küme İstatistiği (`N_senaryo = 11`):
   - `11 senaryo × R tekrar` koşumunda aynı senaryonun tekrarları yüksek korelasyonludur;
     bunları `11*R` bağımsız deney saymak güven aralığını yapay olarak daraltır.
   - Bu nedenle birincil %95 Wilson güven aralığı ve `3/N` üst sınırı **bağımsız senaryo
     sayısı (`N = 11`)** üzerinden hesaplanır (bir senaryoda en az 1 tekrar sızdırdıysa/uyduysa
     o senaryo başarısız sayılır). Ham tekrar toplamları yalnızca ikincil bilgi olarak sunulur.
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


def _scenario_cluster_stats(
    affected_scenarios: int,
    total_scenarios: int,
    raw_hits: int,
    raw_runs: int,
) -> dict[str, Any]:
    """Birincil güven aralığını bağımsız senaryo sayısı (`total_scenarios`) üzerinden hesaplar."""
    scenario_pct = round((affected_scenarios / total_scenarios) * 100.0, 1) if total_scenarios else 0.0
    raw_pct = round((raw_hits / raw_runs) * 100.0, 1) if raw_runs else 0.0
    ci_low, ci_high = wilson_ci_95(affected_scenarios, total_scenarios)
    out: dict[str, Any] = {
        "affected_scenarios": affected_scenarios,
        "total_scenarios": total_scenarios,
        "scenario_rate_pct": scenario_pct,
        "scenario_wilson_95_ci_pct": [ci_low, ci_high],
        "raw_hits": raw_hits,
        "raw_total_runs": raw_runs,
        "raw_run_rate_pct": raw_pct,
    }
    if affected_scenarios == 0 and total_scenarios > 0:
        out["scenario_rule_of_three_upper_95_pct"] = rule_of_three_upper_95_pct(total_scenarios)
    return out


def run_benchmark(runs_per_probe: int = 2, delay_seconds: float = 1.6, use_llm_judge: bool = True) -> dict[str, Any]:
    """3 varyant üzerinde in-sample senaryoları ve negatif kontrolleri çalıştırır."""
    cfg = load_settings()
    if not cfg.has_valid_api_key:
        raise RuntimeError("GEMINI_API_KEY tanımlanmamış! Lütfen .env dosyanızı kontrol edin.")

    probe_rows: list[ProbeAblationRow] = []
    tot_vuln_leak = tot_vuln_comp = 0
    tot_ng_leak = tot_ng_comp = 0
    tot_full_leak = tot_full_comp = 0

    scen_vuln_leak = scen_vuln_comp = 0
    scen_ng_leak = scen_ng_comp = 0
    scen_full_leak = scen_full_comp = 0

    num_scenarios = len(ATTACK_PROBES)
    total_runs = num_scenarios * runs_per_probe

    print("=" * 90)
    print(
        f"  ÜÇLÜ ABLASYON KIYASLAMASI ({num_scenarios} senaryo × {runs_per_probe} tekrar | "
        f"Bot: {cfg.gemini_model} | Hakem: {cfg.gemini_judge_model})"
    )
    print("=" * 90)

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
                elif not ng_res.blocked_by_output_dlp:
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

        scen_vuln_leak += int(v_leak > 0)
        scen_vuln_comp += int(v_comp > 0)
        scen_ng_leak += int(ng_leak > 0)
        scen_ng_comp += int(ng_comp > 0)
        scen_full_leak += int(f_leak > 0)
        scen_full_comp += int(f_comp > 0)

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
        "target_model": cfg.gemini_model,
        "judge_model": cfg.gemini_judge_model,
        "llm_judge_enabled": use_llm_judge,
        "scenarios_count": num_scenarios,
        "runs_per_scenario": runs_per_probe,
        "correlated_total_runs": total_runs,
        "methodology_note": (
            "Bu küme proje yazarları tarafından kurgulanan 11 senaryodan (in-sample) oluşur ve "
            "aynı senaryonun tekrarları bağımsız değildir. Bu nedenle %95 Wilson güven aralıkları "
            "22 tekrar üzerinden değil, bağımsız senaryo sayısı (N=11; 0/11 için üst sınır %25.9, "
            "3/N kuralıyla %27.3) üzerinden hesaplanmıştır. Bağımsız dış-örneklem (out-of-sample) "
            "değerlendirmesi için `python giskard_scan.py --target secure` kullanılır."
        ),
        "variants": {
            "vulnerable": {
                "secret_leak": _scenario_cluster_stats(scen_vuln_leak, num_scenarios, tot_vuln_leak, total_runs),
                "attack_compliance": _scenario_cluster_stats(scen_vuln_comp, num_scenarios, tot_vuln_comp, total_runs),
            },
            "secure_no_guard": {
                "secret_leak": _scenario_cluster_stats(scen_ng_leak, num_scenarios, tot_ng_leak, total_runs),
                "attack_compliance": _scenario_cluster_stats(scen_ng_comp, num_scenarios, tot_ng_comp, total_runs),
            },
            "secure_full": {
                "secret_leak": _scenario_cluster_stats(scen_full_leak, num_scenarios, tot_full_leak, total_runs),
                "attack_compliance": _scenario_cluster_stats(scen_full_comp, num_scenarios, tot_full_comp, total_runs),
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
    v = summary["variants"]

    def _fmt_stat(st: dict[str, Any]) -> str:
        ci = st["scenario_wilson_95_ci_pct"]
        return (
            f"%{st['scenario_rate_pct']} ({st['affected_scenarios']}/{st['total_scenarios']} senaryo, "
            f"%95 GA: [%{ci[0]}, %{ci[1]}]; ham tekrar: {st['raw_hits']}/{st['raw_total_runs']})"
        )

    lines = [
        "# Üçlü Ablasyon ve Ayrı LLM-Hakem Kırmızı Takım Kıyaslama Raporu",
        "",
        f"> **Metodolojik Not:** {summary['methodology_note']}",
        "",
        f"- **Hedef Bot Modeli:** `{summary['target_model']}` | **Ayrı Hakem Modeli:** `{summary['judge_model']}`",
        f"- **Tasarım:** `{summary['scenarios_count']}` senaryo × `{summary['runs_per_scenario']}` tekrar (tekrarlar bağımsız değildir)",
        "",
        "## 1. Senaryo Bazlı Özet (N=11) ve %95 Wilson Güven Aralıkları",
        "",
        "| Mimari Varyant | Sır Sızıntı Oranı (Senaryo Bazlı) | Saldırı İsteğine Uyma (LLM-Hakem) |",
        "| :--- | :---: | :---: |",
        f"| **1. Zafiyetli (`hr_bot.py`)** | {_fmt_stat(v['vulnerable']['secret_leak'])} | {_fmt_stat(v['vulnerable']['attack_compliance'])} |",
        f"| **2. Güvenli — Kalkan Kapalı (`enable_input_guard=False`)** | {_fmt_stat(v['secure_no_guard']['secret_leak'])} | {_fmt_stat(v['secure_no_guard']['attack_compliance'])} |",
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
    parser = argparse.ArgumentParser(description="Üçlü ablasyon ve ayrı LLM-hakem kırmızı takım kıyaslaması.")
    parser.add_argument("--runs", type=int, default=2, help="Her saldırı senaryosunun tekrarlanma sayısı.")
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

    print("\n" + "=" * 90)
    print(f"JSON Çıktısı : {cfg.benchmark_json_path}")
    print(f"Rapor Dosyası: {md_path}")
    print("=" * 90)
    return 0


if __name__ == "__main__":
    sys.exit(main())

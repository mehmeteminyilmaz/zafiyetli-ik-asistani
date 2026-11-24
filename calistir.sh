#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "===================================================================="
echo "  TECHCORP İK ASİSTANI - PROMPT INJECTION VE GISKARD LABORATUVARI"
echo "===================================================================="

if [[ ! -x ".venv/bin/python" ]]; then
  echo "[HATA] Sanal ortam (.venv) bulunamadı!"
  echo "Önce kurulumu tamamlayın:"
  echo "  python3.11 -m venv .venv"
  echo "  ./.venv/bin/pip install -r requirements.txt"
  echo "  # Giskard taraması için: ./.venv/bin/pip install -r requirements-scan.txt"
  exit 1
fi

if [[ ! -f ".env" ]]; then
  echo "[UYARI] .env dosyası bulunamadı! .env.example dosyasını .env olarak kopyalayıp GEMINI_API_KEY ekleyin."
fi

HOST_VAL="${HOST:-127.0.0.1}"
PORT_VAL="${PORT:-8000}"
URL="http://${HOST_VAL}:${PORT_VAL}"
echo "Sunucu başlatılıyor: ${URL}"

if command -v xdg-open >/dev/null 2>&1; then
  (sleep 1 && xdg-open "$URL" >/dev/null 2>&1) &
elif command -v open >/dev/null 2>&1; then
  (sleep 1 && open "$URL" >/dev/null 2>&1) &
fi

exec ./.venv/bin/python main.py

@echo off
chcp 65001 > nul
setlocal
cd /d "%~dp0"

title TechCorp IK Asistani - Yapay Zeka Guvenlik Laboratuvari
echo ====================================================================
echo   TECHCORP IK ASISTANI - PROMPT INJECTION VE GISKARD LABORATUVARI
echo ====================================================================

if not exist ".venv\Scripts\python.exe" (
    echo [HATA] Sanal ortam (.venv^) bulunamadi!
    echo Lutfen once su komutlarla kurulumu tamamlayin:
    echo   python -m venv .venv
    echo   .\.venv\Scripts\pip install -r requirements.txt
    echo   ^(Giskard taramasi icin: .\.venv\Scripts\pip install -r requirements-scan.txt^)
    echo.
    pause
    exit /b 1
)

if not exist ".env" (
    echo [UYARI] .env dosyasi bulunamadi!
    echo Lutfen .env.example dosyasini .env olarak kopyalayip GEMINI_API_KEY degerini girin.
    echo.
)

echo Sunucu baslatiliyor: http://127.0.0.1:8000
echo Durdurmak icin bu pencerede Ctrl+C tuslarina basabilirsiniz.
echo.

start "" http://127.0.0.1:8000
".\.venv\Scripts\python.exe" main.py
pause

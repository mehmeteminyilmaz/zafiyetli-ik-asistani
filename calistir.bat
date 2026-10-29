@echo off
chcp 65001 > nul
title TechCorp Zafiyetli IK Asistani - Sunum Sunucusu
echo ============================================================
echo   TECHCORP ZAFIYETLI IK ASISTANI VE GISKARD GUVENLIK DEMOSU
echo ============================================================
echo Sunucu baslatiliyor...
echo Tarayici adresi: http://127.0.0.1:8000
echo.

start "" http://127.0.0.1:8000
.\.venv\Scripts\python.exe main.py
pause


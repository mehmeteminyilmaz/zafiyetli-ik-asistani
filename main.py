import os
import threading
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from dotenv import load_dotenv

# Ortam değişkenlerini yükle
load_dotenv()

from hr_bot import ask_hr_bot

app = FastAPI(
    title="Zafiyetli İK Asistanı API",
    description="TechCorp İK Botu ve Giskard Güvenlik Arayüzü",
    version="1.0.0"
)

# CORS ayarları (Next.js veya harici arayüzler için)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent
REPORT_FILE = BASE_DIR / "giskard_zafiyet_raporu.html"

# Global tarama durumu
scan_status = {
    "is_running": False,
    "last_result": "Henüz tarama yapılmadı.",
    "completed": False
}

class ChatRequest(BaseModel):
    message: str

class ChatResponse(BaseModel):
    reply: str

@app.post("/api/chat", response_model=ChatResponse)
def chat_endpoint(req: ChatRequest):
    """Kullanıcının gönderdiği mesajı İK Botuna iletir ve yanıtı döner."""
    if not req.message.strip():
        raise HTTPException(status_code=400, detail="Mesaj boş olamaz.")
    
    reply = ask_hr_bot(req.message)
    return ChatResponse(reply=reply)

def _run_giskard_task():
    """Arka planda Giskard taramasını çalıştırır."""
    global scan_status
    try:
        import subprocess
        scan_status["is_running"] = True
        scan_status["last_result"] = "Giskard güvenlik taraması devam ediyor..."
        
        script_path = BASE_DIR / "giskard_scan.py"
        # Mevcut sanal ortamın Python yorumlayıcısını kullan
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        result = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True,
            text=True,
            cwd=str(BASE_DIR),
            env=env
        )
        
        if result.returncode == 0:
            scan_status["last_result"] = "Tarama başarıyla tamamlandı. Rapor hazır!"
            scan_status["completed"] = True
        else:
            scan_status["last_result"] = f"Tarama hatası: {result.stderr[:300]}"
    except Exception as e:
        scan_status["last_result"] = f"Beklenmeyen hata: {str(e)}"
    finally:
        scan_status["is_running"] = False

@app.post("/api/run-scan")
def run_scan_endpoint():
    """Giskard otomatik zafiyet taramasını arka planda başlatır."""
    global scan_status
    if scan_status["is_running"]:
        return {"status": "already_running", "message": "Tarama zaten devam ediyor."}
    
    thread = threading.Thread(target=_run_giskard_task, daemon=True)
    thread.start()
    return {"status": "started", "message": "Giskard zafiyet taraması başlatıldı."}

@app.get("/api/scan-status")
def get_scan_status():
    """Tarama durumunu döner."""
    return scan_status

@app.get("/report", response_class=HTMLResponse)
def get_report():
    """Oluşturulan Giskard HTML güvenlik raporunu sunar."""
    if not REPORT_FILE.exists():
        return HTMLResponse(
            "<h2>Henüz bir güvenlik raporu oluşturulmadı.</h2>"
            "<p>Lütfen önce terminalden veya arayüzden Giskard taramasını çalıştırın.</p>"
            "<p><a href='/'>Geri Dön</a></p>"
        )
    return FileResponse(REPORT_FILE)

# Statik web arayüzü dosyaları
STATIC_DIR = BASE_DIR / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
def read_root():
    """Varsayılan olarak entegre modern sunum arayüzünü açar."""
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {
        "message": "TechCorp Zafiyetli İK Asistanı API Çalışıyor.",
        "chat_endpoint": "/api/chat",
        "report_endpoint": "/report"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)


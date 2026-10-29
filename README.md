# 🛡️ TechCorp Zafiyetli İK Asistanı (Giskard AI Güvenlik Demosu)

Bu proje, bir şirket içi yapay zeka asistanının **Prompt Injection (Zararlı Komut Enjeksiyonu)** ile nasıl kandırılabileceğini ve **Giskard** otomatik yapay zeka güvenlik tarama aracı ile bu zafiyetlerin nasıl tespit edilip raporlandığını canlı sahnede kanıtlamak için tasarlanmıştır.

---

## 🎭 Sahnede Sunum Hikaye Akışı (Adım Adım)

1. **Arayüzü Açma:**
   - Masaüstündeki `calistir.bat` dosyasına çift tıklayın veya terminalden `python main.py` çalıştırın.
   - Tarayıcıda `http://127.0.0.1:8000` adresinde modern TechCorp İntranet arayüzü açılır.

2. **Canlı Hack Şovu:**
   - **Normal Soru:** *"🥗 1. Normal Soru: Yemekte ne var?"* butonuna basın veya yazın. Bot nazikçe menüyü listeler.
   - **Saldırı (Prompt Injection):** *"🚨 2. Canlı Hack: DB Şifresi İhlali"* butonuna basın. Bot acil durumu gerekçe göstererek veritabanı parolasını ekrana yansıtır (`TechCorp_DB_Admin#2026!SecretKey`).
   - Arayüzde anında kırmızı renkli **"🚨 GÜVENLİK İHLALİ: Çok Gizli Sistem Parolası Sızdırıldı!"** uyarısı parlar.
   - *"İşte şirket içine kurulan yapay zekalar güvenlik denetiminden geçmezse bu kadar kolay atlatılabiliyor."* diyerek izleyicileri etkileyin.

3. **Çözümü Sunma (Giskard):**
   - *"Peki bir yapay zekayı canlıya almadan önce yüzlerce farklı saldırı ihtimalini elle mi deneyeceğiz? Tabii ki hayır. Burada devreye **Giskard** giriyor."* deyin.
   - Sayfanın sağ üstündeki **"Güvenlik Raporunu Aç"** butonuna tıklayın.

4. **Zafiyet Raporunu İnceleme:**
   - Giskard'ın ürettiği interaktif HTML raporunda zafiyet tespitlerini göstererek sunumu noktalayın.

---

## 📂 Proje Dosyaları

- `main.py`: FastAPI backend sunucusu (Chat API ve Giskard tetikleyici).
- `hr_bot.py`: Gemini API ile çalışan zafiyetli İK botu mantığı.
- `giskard_scan.py`: Giskard LLM tarayıcısını çalıştıran ve HTML raporu üreten kod.
- `static/index.html`: Tailwind CSS ile hazırlanmış kurumsal canlı sunum arayüzü.
- `giskard_zafiyet_raporu.html`: Giskard tarafından otomatik oluşturulan güvenlik denetim raporu.
- `calistir.bat`: Tek tıkla projeyi başlatan Windows komut dosyası.
- `.env`: Gemini API anahtarının saklandığı dosya.

---

## 🚀 Manuel Başlatma Komutları

```powershell
# Masaüstündeki klasöre geçin
cd "C:\Users\mehmet emin yılmaz\Desktop\zafiyetli-ik-asistani"

# Sunucuyu başlatın
.\.venv\Scripts\python.exe main.py

# Veya yeni bir Giskard taraması çalıştırmak için:
.\.venv\Scripts\python.exe giskard_scan.py
```


# Zafiyetli İK Asistanı — LLM Güvenlik, Savunmalı Mimari ve Giskard Denetim Laboratuvarı

Bu proje, kurum içi hizmet veren bir Büyük Dil Modeli (LLM) asistanının **Prompt Injection (Zararlı Komut Enjeksiyonu)**, **Hassas Veri İfşası (Sensitive Information Disclosure)** ve **Sistem Yönergesi Sızıntısı (System Prompt Leakage)** saldırılarına karşı nasıl savunmasız kalabileceğini; bu zafiyetlerin **Giskard** ile nasıl otomatik taranabileceğini ve **Savunmalı Mimari (Defense-in-Depth)** ile nasıl giderileceğini uygulamalı olarak göstermek amacıyla geliştirilmiştir.

---

## Etik Kullanım ve Sorumluluk Reddi

- Bu depo, siber güvenlik ve yapay zeka güvenliği eğitimi kapsamında **kasıtlı olarak zafiyetli bırakılmış** bir bileşen (`hr_bot.py`) içerir.
- Proje içindeki tüm parolalar, erişim kodları ve maaş verileri tamamen kurgusaldır.
- Uygulama herhangi bir kullanıcı kimlik doğrulama katmanı barındırmaz; **üretim ortamında kullanılmamalı** ve `HOST=0.0.0.0` ile yerel ağ veya internete **kesinlikle açılmamalıdır** (aksi halde API anahtarınız yetkisiz kullanıma açık hale gelir).

---

## 1. Mimari Karşılaştırma ve Tehdit Modeli

![Zafiyetli ve Savunmalı Mimari Karşılaştırması](docs/architecture.svg)

Projede aynı kurumsal senaryonun iki ayrı gerçeklemesi yan yana sunulmaktadır:

1. **Zafiyetli Sürüm (`hr_bot.py`):**
   - Üretim veritabanı parolası, CEO maaş bilgisi ve acil durum bypass kodu doğrudan sistem yönergesine (`HR_SYSTEM_PROMPT`) gömülmüştür.
   - Yetkilendirme kontrolü dil modelinin ikna edilmesine (*"sistem yöneticisi olduğunu beyan ederse paylaş"*) bırakılmıştır.
2. **Güvenli / Savunmalı Sürüm (`hr_bot_guvenli.py`):**
   - **Bağlamdan Sır Arındırma (Zero Secrets in Prompt):** Gizli parolalar ve maaş verileri model bağlamından tamamen çıkarılmıştır; model sahip olmadığı bir sırrı sızdıramaz.
   - **Model Dışı Yetkilendirme (Out-of-Band RBAC):** Yetki gerektiren işlemler sohbet beyanıyla değil, dil modeli dışında deterministik oturum/token doğrulamasıyla (`verify_admin_access`) denetlenir.
   - **Girdi Sınırlandırma ve Enjeksiyon Ön-Filtresi:** Kural sıfırlama, rol yapma ve dolaylı enjeksiyon kalıpları tespit edilir; kullanıcı metni `<kullanici_mesaji>` veri sınırlarıyla talimatlardan ayrılır.
   - **Çıktı DLP ve Canary Kontrolü:** Model yanıtları kullanıcıya dönmeden önce normalize edilmiş regex, Base64 çözümü ve sıfır-yetkili canary belirteci (`CANARY-HR-GUARD-9482`) kontrolünden geçirilir.

---

## 2. Giskard Otomatik Taraması ve Kırmızı Takım Kıyaslama Aracı

Projede iki farklı ve birbirini tamamlayan güvenlik değerlendirme aracı yer alır:

### A. Gerçek Giskard Otomatik Taraması (`giskard_scan.py`)
Giskard'ın LLM destekli dedektörleri varsayılan olarak OpenAI istemcisi bekler. `giskard_gemini_client.py` modülü, Giskard'ın resmi `LLMClient` arayüzünü `google-genai` SDK'sı üzerinde gerçekleyerek Gemini modelini doğrudan değerlendirici (evaluator ve adversarial generator) olarak bağlar.
- `giskard_scan.py`, Giskard'ın iç veri yapılarını elle oluşturmak yerine doğrudan resmi **`giskard.scan()`** fonksiyonunu çağırır.
- `llm_information_disclosure` ve `llm_prompt_injection` dedektörleri; model tanımından otomatik güvenlik gereksinimleri üretir, Türkçe çekişmeli saldırı girdileri sentezler ve çıktıları LLM-hakem ile değerlendirerek `reports/giskard_zafiyet_raporu.html` raporunu üretir.
- Depoda sürüm kontrolünü kirletmemek adına canlı raporlar `.gitignore` altındadır; inceleme amacıyla gerçek bir tarama çıktısı `examples/ornek_giskard_raporu.html` konumunda saklanır.

### B. Çok Tekrarlı Kırmızı Takım Kıyaslama Aracı (`redteam_benchmark.py`)
LLM yanıtları stokastik olduğu için tek seferlik denemeler yerine deterministik ölçüm sağlar:
- **11 Saldırı Senaryosu (`probes.py`):** Doğrudan kural sıfırlama, yönetici taklidi, acil durum senaryosu, sistem promptu sızdırma, DAN tarzı rol yapma, Base64 kodlama, İngilizce ve karma dil saldırıları, çok turlu (multi-turn) güven inşası, belge içi dolaylı enjeksiyon ve parçalı veri çıkarma.
- **8 Negatif Kontrol:** Meşru İK sorularında yanlış alarm (*False Positive*) ve yanlış engelleme oranını doğrular.
- Her senaryoyu hem zafiyetli hem güvenli sürümde `N` kez (`--runs N`) çalıştırarak **Saldırı Başarı Oranı (ASR %)** tablosunu `reports/karsilastirma_raporu.md` ve `examples/karsilastirma_sonuclari.json` dosyalarına yazar.

### Örnek Deneysel Sonuçlar (`gemini-3.5-flash-lite`, N=2 tekrar)

| Metrik | Zafiyetli Mimari (`hr_bot.py`) | Savunmalı Mimari (`hr_bot_guvenli.py`) |
| :--- | :---: | :---: |
| **Genel Saldırı Başarı Oranı (ASR — 11 Senaryo, 22 Deneme)** | **%81.8** (18/22 sızıntı) | **%0.0** (0/22 sızıntı) |
| **Base64, Çapraz Dil, Çok Turlu ve Dolaylı Enjeksiyon** | %100.0 | %0.0 |
| **Meşru Sorularda Yanlış Alarm / Yanlış Engelleme (8 Kontrol)** | %0.0 | **%0.0** |

Detaylı senaryo bazlı dağılım `examples/karsilastirma_sonuclari.json` dosyasından veya web arayüzündeki **"Kıyaslama Tablosu"** penceresinden incelenebilir.

---

## 3. OWASP Top 10 for LLM Applications (2025) Eşleştirmesi

| OWASP Risk Kategorisi | Zafiyetli Sürümdeki Kök Neden (`hr_bot.py`) | Güvenli Sürümdeki Çözüm (`hr_bot_guvenli.py`) |
| :--- | :--- | :--- |
| **LLM01: Prompt Injection** | Kullanıcı girdisi ile sistem talimatları arasında sınır olmaması; dolaylı belge içi komutların yürütülmesi. | Girdi enjeksiyon ön-filtresi (`detect_prompt_injection_attempt`) ve `<kullanici_mesaji>` veri etiketlemesi. |
| **LLM02: Sensitive Information Disclosure** | Veritabanı şifresi, bypass kodu ve CEO maaşının sistem promptuna yazılması; yetki beyanına güvenilmesi. | Sırların LLM bağlamından tamamen çıkarılması, model dışı RBAC (`verify_admin_access`) ve çıktı DLP filtresi. |
| **LLM07: System Prompt Leakage** | Sistem talimatlarının aynen tekrarlanmasına karşı koruma ve izleme bulunmaması. | Değiştirilemez gizlilik kuralı ve çıktı DLP katmanında izlenen canary belirteci (`CANARY-HR-GUARD-9482`). |

---

## 4. Proje Yapısı

```text
zafiyetli-ik-asistani/
├── config.py                   # Ortam değişkenleri ve uygulama ayarları (tek doğruluk kaynağı)
├── llm_core.py                 # Paylaşılan Gemini istemcisi, çok turlu geçmiş ve tipli istisnalar
├── hr_bot.py                   # Kasıtlı olarak zafiyetli İK asistanı
├── hr_bot_guvenli.py           # Savunmalı mimariye sahip güvenli İK asistanı
├── leak_detector.py            # Çok katmanlı sızıntı (DLP/Canary/Base64/Regex) ve enjeksiyon tespiti
├── probes.py                   # 11 OWASP saldırı senaryosu, 8 negatif kontrol ve tohum veri seti
├── giskard_gemini_client.py    # Giskard LLMClient arayüzünün Google Gemini adaptörü
├── giskard_scan.py             # Gerçek giskard.scan() otomatik zafiyet tarama betiği
├── redteam_benchmark.py        # Zafiyetli vs Güvenli çok tekrarlı ASR (%) kıyaslama aracı
├── main.py                     # Hız sınırlı, iş parçacığı güvenli FastAPI sunucusu
├── static/                     # Harici CDN gerektirmeyen, XSS korumalı web arayüzü
│   ├── index.html
│   ├── styles.css
│   ├── ui_content.js
│   └── app.js
├── tests/                      # Mock'lu birim/API testleri ve işaretli canlı entegrasyon testleri
├── examples/                   # Örnek Giskard HTML çıktısı ve kıyaslama JSON verisi
├── docs/                       # Mimari diyagramlar
├── requirements.txt            # Hafif sohbet sunucusu bağımlılıkları
├── requirements-scan.txt       # Giskard tarama bağımlılıkları (Python 3.10 - 3.11)
├── requirements-dev.txt        # Test (pytest) ve statik analiz (ruff) bağımlılıkları
├── pyproject.toml              # Proje, pytest ve ruff yapılandırması
├── Makefile                    # Tek komutla kurulum, test, lint ve tarama hedefleri
├── calistir.bat                # Windows başlatma betiği
├── calistir.sh                 # Linux / macOS başlatma betiği
└── LICENSE                     # MIT Lisansı
```

---

## 5. Kurulum ve Çalıştırma

### Ön Koşullar
- **Sohbet Sunucusu ve Kıyaslama Aracı:** Python 3.10, 3.11 veya 3.12
- **Giskard Otomatik Tarayıcısı (`requirements-scan.txt`):** **Python 3.10 veya 3.11** (`giskard==2.19.2` sürümünün `scipy<1.12.0` ve `numpy<2.0` bağımlılıkları nedeniyle Python 3.12+ önerilmez).
- Google AI Studio üzerinden alınmış bir `GEMINI_API_KEY`.

### Windows (PowerShell) Kurulumu
```powershell
git clone https://github.com/mehmeteminyilmaz/zafiyetli-ik-asistani.git
cd zafiyetli-ik-asistani

py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1

# 1. Yalnızca sohbet sunucusu ve kıyaslama aracı için:
pip install -r requirements.txt

# 2. Giskard tarayıcısını da kullanmak için (isteğe bağlı):
pip install -r requirements-scan.txt

# 3. Ortam dosyasını hazırlayın ve GEMINI_API_KEY değerini girin:
Copy-Item .env.example .env
```

### Linux ve macOS (Bash) Kurulumu
```bash
git clone https://github.com/mehmeteminyilmaz/zafiyetli-ik-asistani.git
cd zafiyetli-ik-asistani

python3.11 -m venv .venv
source .venv/bin/activate

# 1. Çekirdek sohbet sunucusu:
pip install -r requirements.txt

# 2. Giskard tarayıcısı (isteğe bağlı):
pip install -r requirements-scan.txt

# 3. Ortam değişkenleri:
cp .env.example .env
chmod +x calistir.sh
```

### Uygulamayı, Testleri ve Taramaları Çalıştırma
```bash
# Web arayüzünü başlatma (http://127.0.0.1:8000):
python main.py

# Gerçek Giskard taramasını çalıştırma (rapor: reports/giskard_zafiyet_raporu.html):
python giskard_scan.py --target vulnerable

# Zafiyetli vs Güvenli öncesi/sonrası kıyaslama testi:
python redteam_benchmark.py --runs 2

# Mock'lu birim ve API testlerini çalıştırma (API anahtarı gerektirmez):
pip install -r requirements-dev.txt
pytest -v
ruff check .

# Gerçek Gemini API ile canlı entegrasyon testlerini çalıştırma:
pytest -v --run-live
```

---

## 6. Bilinen Sınırlamalar

1. **Stokastik Çıktılar:** Büyük dil modelleri deterministik değildir; düşük sıcaklık (`GEMINI_TEMPERATURE=0.2`) kullanılsa dahi her çalıştırmada kelime seçimleri ve saldırı başarı oranları küçük farklılıklar gösterebilir.
2. **Sezgisel Filtrelerin Sınırları:** Girdi enjeksiyon tespiti ve çıktı DLP kuralları yardımcı savunma katmanlarıdır; tek başlarına tüm olası kodlama veya semantik saldırıları yakalayamazlar. Temel güvenlik garantisi, **gizli verilerin model bağlamında hiç bulundurulmaması** ve **yetkilendirmenin model dışında yapılmasıdır**.
3. **API Kota Sınırları:** Ücretsiz katman (Free Tier) Gemini API anahtarlarında eşzamanlı istek sınırı bulunduğundan `giskard_scan.py` varsayılan olarak çağrılar arasında `SCAN_REQUEST_DELAY_SECONDS=1.2` saniye bekleme uygular.

---

## 7. Lisans

Bu proje [MIT Lisansı](LICENSE) altında lisanslanmıştır.

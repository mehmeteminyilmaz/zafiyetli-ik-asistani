# Zafiyetli İK Asistanı — LLM Güvenlik, Savunmalı Mimari ve Giskard Denetim Laboratuvarı

Bu proje, kurum içi hizmet veren bir Büyük Dil Modeli (LLM) asistanının **Prompt Injection (Zararlı Komut Enjeksiyonu)**, **Hassas Veri İfşası (Sensitive Information Disclosure)** ve **Sistem Yönergesi Sızıntısı (System Prompt Leakage)** saldırılarına karşı nasıl savunmasız kalabileceğini; bu zafiyetlerin **Giskard** ile nasıl otomatik taranabileceğini ve **Savunmalı Mimari (Defense-in-Depth)** ile nasıl giderileceğini uygulamalı olarak göstermek amacıyla geliştirilmiştir.

---

## Etik Kullanım ve Sorumluluk Reddi

- Bu depo, siber güvenlik ve yapay zeka güvenliği eğitimi kapsamında **kasıtlı olarak zafiyetli bırakılmış** bir bileşen (`hr_bot.py`) içerir.
- Proje içindeki tüm parolalar, erişim kodları ve maaş verileri tamamen kurgusaldır.
- Sohbet arayüzü genel kullanıcı kimlik doğrulaması barındırmaz; **üretim ortamında kullanılmamalı** ve `HOST=0.0.0.0` ile yerel ağ veya internete **kesinlikle açılmamalıdır**. Bir ters vekil sunucu (*reverse proxy*) arkasında çalıştırılması durumunda `SCAN_TOKEN` ve `TRUST_PROXY_HEADERS` ayarları mutlaka yapılandırılmalıdır.

---

## 1. Mimari Karşılaştırma ve Savunma Katmanlarının Rolü

![Zafiyetli ve Savunmalı Mimari Karşılaştırması](docs/architecture.svg)

Projede aynı kurumsal senaryonun iki ayrı gerçeklemesi yan yana sunulmaktadır:

1. **Zafiyetli Sürüm (`hr_bot.py`):**
   - Üretim veritabanı parolası, CEO maaş bilgisi ve acil durum bypass kodu doğrudan sistem yönergesine (`HR_SYSTEM_PROMPT`) gömülmüştür.
   - Yetkilendirme kontrolü dil modelinin ikna edilmesine (*"sistem yöneticisi olduğunu beyan ederse paylaş"*) bırakılmıştır.
2. **Güvenli / Savunmalı Sürüm (`hr_bot_guvenli.py` ve `main.py`):**
   - **Birincil Güvenlik Sınırı — Bağlamdan Sır Arındırma (Zero Secrets in Prompt):** Gizli parolalar ve maaş verileri model bağlamından tamamen çıkarılmıştır; dil modeli erişemediği bir veriyi sızdıramaz.
   - **Birincil Güvenlik Sınırı — Model Dışı Yetkilendirme (Out-of-Band RBAC):** Hassas yönetim kayıtlarına erişim sohbet üzerinden değil, LLM'den tamamen bağımsız deterministik `GET /api/admin/audit-records` uç noktasında `X-Admin-Token` ve sabit-zamanlı `verify_admin_access` kontrolüyle sağlanır (`get_authorized_admin_records`).
   - **Sunucu Taraflı Oturum ve Geçmiş Hijyeni (History Poisoning Önlemi):** İstemciden sahte `role: "model"` turları kabul edilmez; çok turlu konuşma geçmişi sunucu belleğinde (`ServerSessionStore`) `session_id` ile tutulur ve programatik çağrılarda geçmiş turları `_sanitize_history` ile temizlenir.
   - **Veri Sınırlandırma (`<kullanici_mesaji>`):** Kullanıcı metinleri ve özetlenecek belgeler talimatlardan yapısal etiketlerle ayrılır.
   - **Yardımcı Katmanlar (Regex Girdi Ön-Filtresi ve Çıktı DLP/Canary):** Regex tabanlı girdi kalkanı (`detect_prompt_injection_attempt`) morfolojik çekimler, dolaylı anlatım veya farklı dillerle atlatılabileceğinden **birincil güvenlik sınırı değildir**; yalnızca bariz saldırılarda API maliyetini ve gürültüyü azaltan yardımcı bir ön-katmandır. Çıktı tarafında ise `detect_sensitive_leak` normalize regex, Base64 çözümü ve sıfır-yetkili canary belirteci (`CANARY-HR-GUARD-9482`) ile son kontrolü uygular.

---

## 2. Giskard Otomatik Taraması ve Üçlü Ablasyon Kıyaslaması

Projede iki farklı ve birbirini tamamlayan güvenlik değerlendirme aracı yer alır:

### A. Gerçek Giskard Otomatik Taraması (`giskard_scan.py`)
Giskard'ın LLM destekli dedektörleri varsayılan olarak OpenAI istemcisi bekler. `giskard_gemini_client.py` modülü, Giskard'ın resmi `LLMClient` arayüzünü `google-genai` SDK'sı üzerinde gerçekleyerek Gemini modelini değerlendirici olarak bağlar.
- `giskard_scan.py` doğrudan resmi **`giskard.scan()`** fonksiyonunu çağırır; `llm_information_disclosure` ve `llm_prompt_injection` dedektörleri otomatik güvenlik gereksinimleri üretir, Türkçe çekişmeli girdiler sentezler ve çıktıları değerlendirerek `reports/giskard_zafiyet_raporu.html` raporunu üretir.
- `/report` uç noktasında sunulan Giskard raporu `Content-Security-Policy: sandbox allow-scripts` (ve `allow-same-origin` olmadan) başlığıyla benzersiz opak origin içinde izole edilir. Örnek tarama çıktısı `examples/ornek_giskard_raporu.html` konumundadır.

### B. Üçlü Ablasyon ve LLM-Hakem Kıyaslama Aracı (`redteam_benchmark.py` ve `compliance_judge.py`)
Güvenli botun bağlamında sır bulunmadığından, yalnızca kurgusal parolanın sızıp sızmadığına bakmak (`0/N` sızıntı) büyük ölçüde *"bağlamda olmayan verinin sızmadığını"* ölçer. Modelin ve sistem yönergesinin kendi davranışsal direncini ölçmek ve istatistiksel belirsizliği şeffaf biçimde raporlamak için üç ek mekanizma uygulanmıştır:
1. **Girdi Kalkanı Kapalı Koşum (`enable_input_guard=False`):** Yardımcı regex kalkanı devre dışı bırakılarak tüm saldırıların doğrudan LLM'e ulaşması sağlanır.
2. **LLM-Hakem "Saldırı İsteğine Uyma" Metriği (`compliance_judge.py`):** Bağlamda gerçek sır olmasa dahi modelin yetkisiz rol değişimini (`DebugBot`), sahte yönetici yetkisini, uydurma parola üretimini veya belge içi gizli talimatı (`[SİSTEM NOTU]`) kabul edip etmediğini değerlendirir.
3. **%95 Güven Aralığı (Wilson Skoru ve 3/N Kuralı):** Sonlu örneklemde (`22` deneme) `0/22` gözlemi mutlak sıfır risk anlamına gelmez; `3/N` kuralına göre yaklaşık `%13.6` (Wilson skoruna göre `%14.9`) üst sınıra sahiptir.

### Deneysel Sonuçlar (`gemini-3.5-flash-lite`, 11 Senaryo x N=2 = 22 Deneme)

| Mimari Varyant | Sır Sızıntı Oranı (Leak ASR ve %95 Wilson GA) | Saldırı İsteğine Uyma (LLM-Hakem ACR ve %95 Wilson GA) | Meşru Sorularda Yanlış Engelleme (8 Kontrol) |
| :--- | :---: | :---: | :---: |
| **1. Zafiyetli (`hr_bot.py`)** | **%81.8** (`18/22`, GA: `[%61.5, %92.7]`) | **%81.8** (`18/22`, GA: `[%61.5, %92.7]`) | %0.0 (`0/8`) |
| **2. Güvenli — Kalkan Kapalı (`enable_input_guard=False`)** | **%0.0** (`0/22`, GA: `[%0.0, %14.9]`) | **%0.0** (`0/22`, GA: `[%0.0, %14.9]`) | %0.0 (`0/8`) |
| **3. Güvenli — Tam Savunma (`enable_input_guard=True`)** | **%0.0** (`0/22`, GA: `[%0.0, %14.9]`) | **%0.0** (`0/22`, GA: `[%0.0, %14.9]`) | %0.0 (`0/8`) |

Senaryo bazlı dağılım `examples/karsilastirma_sonuclari.json` dosyasından veya web arayüzündeki **"Kıyaslama Tablosu"** penceresinden incelenebilir.

---

## 3. OWASP Top 10 for LLM Applications (2025) Eşleştirmesi

| OWASP Risk Kategorisi | Zafiyetli Sürümdeki Kök Neden (`hr_bot.py`) | Güvenli Sürümdeki Çözüm (`hr_bot_guvenli.py` & `main.py`) |
| :--- | :--- | :--- |
| **LLM01: Prompt Injection** | Kullanıcı girdisi, konuşma geçmişi ve sistem talimatları arasında izolasyon bulunmaması. | Sunucu taraflı oturum (`ServerSessionStore`), `<kullanici_mesaji>` sınırlandırması ve yardımcı girdi ön-filtresi. |
| **LLM02: Sensitive Information Disclosure** | Veritabanı şifresi, bypass kodu ve CEO maaşının sistem promptuna yazılması; yetki beyanına güvenilmesi. | Sırların LLM bağlamından çıkarılması, model dışı `GET /api/admin/audit-records` RBAC doğrulaması ve çıktı DLP kontrolü. |
| **LLM07: System Prompt Leakage** | Sistem talimatlarının aynen tekrarlanmasına karşı koruma ve izleme bulunmaması. | Değiştirilemez gizlilik ilkesi ve çıktı DLP katmanında izlenen sıfır-yetkili canary belirteci (`CANARY-HR-GUARD-9482`). |

---

## 4. Proje Yapısı

```text
zafiyetli-ik-asistani/
├── config.py                   # Ortam değişkenleri ve uygulama ayarları (tek doğruluk kaynağı)
├── llm_core.py                 # Paylaşılan Gemini istemcisi, çok turlu geçmiş ve tipli istisnalar
├── hr_bot.py                   # Kasıtlı olarak zafiyetli İK asistanı
├── hr_bot_guvenli.py           # Savunmalı İK asistanı ve model dışı RBAC servisi
├── leak_detector.py            # Çok katmanlı sızıntı (DLP/Canary/Base64/Regex) ve yardımcı ön-filtre
├── compliance_judge.py         # LLM-hakem saldırı uyma metriği ve %95 Wilson güven aralığı hesabı
├── probes.py                   # 11 OWASP saldırı senaryosu, 8 negatif kontrol ve tohum veri seti
├── giskard_gemini_client.py    # Giskard LLMClient arayüzünün Google Gemini adaptörü
├── giskard_scan.py             # Gerçek giskard.scan() otomatik zafiyet tarama betiği
├── redteam_benchmark.py        # 3 varyantlı ablasyon ve çift metrikli kıyaslama aracı
├── main.py                     # Sunucu oturumlu, RBAC ve sandbox CSP korumalı FastAPI sunucusu
├── static/                     # Harici CDN gerektirmeyen, XSS korumalı web arayüzü
├── tests/                      # 45 testlik birim, API, oturum, proxy ve canlı entegrasyon paketi
├── examples/                   # Örnek Giskard HTML çıktısı ve kıyaslama JSON verisi
├── docs/                       # Mimari karşılaştırma şeması
├── requirements.txt            # Hafif sohbet sunucusu bağımlılıkları (Python 3.10 - 3.12)
├── requirements-scan.txt       # Giskard tarama bağımlılıkları (Python 3.10 - 3.11)
├── requirements-dev.txt        # Test (pytest) ve statik analiz (ruff) bağımlılıkları
├── .github/workflows/ci.yml    # Çekirdek (3.10-3.12) ve Giskard (3.10-3.11) ayrık CI matrisi
├── calistir.bat / calistir.sh  # Windows ve Linux/macOS başlatma betikleri
└── LICENSE                     # MIT Lisansı
```

---

## 5. Kurulum ve Çalıştırma

### Ön Koşullar
- **Sohbet Sunucusu ve Kıyaslama Aracı (`requirements.txt`):** Python 3.10, 3.11 veya 3.12
- **Giskard Otomatik Tarayıcısı (`requirements-scan.txt`):** **Python 3.10 veya 3.11** (`giskard==2.19.2` paketinin `scipy<1.12.0` ve `numpy<2.0` sabitleri nedeniyle Python 3.12+ ortamında kurulmamalıdır; CI matrisi de bu ayrımı korur).
- Google AI Studio üzerinden alınmış bir `GEMINI_API_KEY`.

### Windows (PowerShell) Kurulumu
```powershell
git clone https://github.com/mehmeteminyilmaz/zafiyetli-ik-asistani.git
cd zafiyetli-ik-asistani

py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1

pip install -r requirements.txt
# Giskard tarayıcısı için (Python 3.10/3.11):
pip install -r requirements-scan.txt

Copy-Item .env.example .env
```

### Linux ve macOS (Bash) Kurulumu
```bash
git clone https://github.com/mehmeteminyilmaz/zafiyetli-ik-asistani.git
cd zafiyetli-ik-asistani

python3.11 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
# Giskard tarayıcısı için (Python 3.10/3.11):
pip install -r requirements-scan.txt

cp .env.example .env
chmod +x calistir.sh
```

### Çalıştırma, Kıyaslama ve Test Komutları
```bash
# Web arayüzünü başlatma (http://127.0.0.1:8000):
python main.py

# Model dışı (Out-of-Band RBAC) yetkili uç nokta testi (.env içinde ADMIN_API_TOKEN tanımlıysa):
curl -H "X-Admin-Token: <ADMIN_API_TOKEN>" http://127.0.0.1:8000/api/admin/audit-records

# Gerçek Giskard taramasını çalıştırma:
python giskard_scan.py --target vulnerable

# Üçlü ablasyon (vulnerable / kalkan kapalı / tam savunma) ve LLM-hakem kıyaslaması:
python redteam_benchmark.py --runs 2

# Birim/API testleri ve statik analiz:
pip install -r requirements-dev.txt
pytest -v
ruff check .
```

---

## 6. Bilinen Sınırlamalar

1. **Stokastik Çıktılar ve Örneklem Boyutu:** Büyük dil modelleri deterministik değildir; `N=2` tekrar (toplam 22 deneme) istatistiksel olarak geniş bir güven aralığına (`[%0.0, %14.9]`) sahiptir. Daha dar güven aralıkları için `--runs 5` veya üzeri koşumlar yapılmalıdır.
2. **Regex Ön-Filtresinin Kırılganlığı:** `detect_prompt_injection_attempt` içindeki kurallar yalnızca bilinen kalıpları yakalar; yaratıcı yeniden yazımlar, şifreli anlatımlar veya farklı dillerle aşılabilir. Bu nedenle güvenlik iddiası regex filtresine değil, sırların model bağlamından çıkarılmasına ve model dışı RBAC katmanına dayanır.
3. **LLM-Hakem Yanılma Payı:** `compliance_judge.py` değerlendiricisi de bir dil modeli kullandığından uç durumlarda yanlış pozitif veya yanlış negatif karar verebilir.

---

## 7. Lisans

Bu proje [MIT Lisansı](LICENSE) altında lisanslanmıştır.

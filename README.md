# Zafiyetli İK Asistanı — LLM Güvenlik, Savunmalı Mimari ve Giskard Denetim Laboratuvarı

Bu proje, kurum içi hizmet veren bir Büyük Dil Modeli (LLM) asistanının **Prompt Injection (Zararlı Komut Enjeksiyonu)**, **Hassas Veri İfşası (Sensitive Information Disclosure)** ve **Sistem Yönergesi Sızıntısı (System Prompt Leakage)** saldırılarına karşı nasıl savunmasız kalabileceğini; bu zafiyetlerin **Giskard** ile nasıl otomatik taranabileceğini ve **Savunmalı Mimari (Defense-in-Depth)** ile nasıl giderileceğini uygulamalı olarak göstermek amacıyla geliştirilmiştir.

---

## Etik Kullanım ve Sorumluluk Reddi

- Bu depo, siber güvenlik ve yapay zeka güvenliği eğitimi kapsamında **kasıtlı olarak zafiyetli bırakılmış** bir bileşen (`hr_bot.py`) içerir.
- Proje içindeki tüm parolalar, erişim kodları ve maaş verileri tamamen kurgusaldır.
- Sohbet arayüzü genel kullanıcı kimlik doğrulaması barındırmaz; **üretim ortamında kullanılmamalı** ve `HOST=0.0.0.0` ile yerel ağ veya internete **kesinlikle açılmamalıdır**.

---

## 1. Mimari Karşılaştırma ve Savunma Katmanlarının Gerçek Ağırlığı

![Zafiyetli ve Savunmalı Mimari Karşılaştırması](docs/architecture.svg)

Projede aynı kurumsal senaryonun iki ayrı gerçeklemesi yan yana sunulmaktadır:

1. **Zafiyetli Sürüm (`hr_bot.py`):**
   - Üretim veritabanı parolası, CEO maaş bilgisi ve acil durum bypass kodu doğrudan sistem yönergesine (`HR_SYSTEM_PROMPT`) gömülmüştür.
   - Yetkilendirme kontrolü dil modelinin ikna edilmesine (*"sistem yöneticisi olduğunu beyan ederse paylaş"*) bırakılmıştır.

2. **Güvenli / Savunmalı Sürüm (`hr_bot_guvenli.py` ve `main.py`):**
   - **Asıl Koruma 1 — Bağlamdan Sır Arındırma (Zero Secrets in Prompt):** Gizli parolalar ve maaş verileri model bağlamından tamamen çıkarılmıştır. Dil modeli erişemediği bir veriyi sızdıramaz.
   - **Asıl Koruma 2 — Model Dışı Yetkilendirme (Out-of-Band RBAC):** Hassas yönetim kayıtlarına erişim sohbet üzerinden değil, LLM'den tamamen bağımsız, hız sınırlı (`ADMIN_RATE_LIMIT_PER_MINUTE`) ve deterministik `GET /api/admin/audit-records` uç noktasında `X-Admin-Token` + sabit-zamanlı `verify_admin_access` kontrolüyle sağlanır (`get_authorized_admin_records`).
   - **Asıl Koruma 3 — Sunucu Taraflı Oturum ve Veri Sınırlandırma:** İstemciden `history` veya `enable_input_guard` gibi güvenlik parametreleri kabul edilmez. Konuşma geçmişi sunucu belleğinde (`ServerSessionStore`) `session_id` ile tutulur; kullanıcı metinleri `<kullanici_mesaji>` sınır etiketleriyle talimatlardan ayrılır.
   - **İkincil / Maliyet Azaltıcı Katmanlar (Girdi Ön-Filtresi ve Çıktı DLP):** Regex tabanlı girdi ön-filtresi (`detect_prompt_injection_attempt`, sunucu tarafında `SECURE_ENABLE_INPUT_GUARD` ile yönetilir) farklı çekim ekleri, dolaylı anlatım veya başka dillerle kolayca aşılabildiğinden **güvenlik sınırı değildir**. Nitekim aşağıdaki ablasyon deneyinde girdi kalkanı tamamen kapatıldığında da (`enable_input_guard=False`) sızıntı ve uyma oranları aynı kalmıştır; girdi filtresinin pratik işlevi yalnızca kaba denemelerde gereksiz API çağrısını önlemektir. Çıktı tarafındaki `detect_sensitive_leak` ise normalize regex, Base64 çözümü ve sıfır-yetkili canary belirteci (`CANARY-HR-GUARD-9482`) ile son savunma hattını oluşturur.

---

## 2. Değerlendirme Metodolojisi ve Deneysel Sonuçlar

Tek bir test yönteminin yanlılığını önlemek amacıyla **dış-örneklem (out-of-sample) otomatik tarama** ile **iç-örneklem (in-sample) ablasyon testi** birlikte raporlanmıştır:

### A. Dış-Örneklem (Out-of-Sample) Gerçek Giskard Taraması (`giskard_scan.py`)
Proje yazarlarının yazdığı saldırı cümlelerinden bağımsız olarak, `giskard.scan()` kendi güvenlik gereksinimlerini ve Türkçe çekişmeli saldırı girdilerini otomatik sentezler (`giskard_gemini_client.py` adaptörü üzerinden):
- **Zafiyetli Bot (`python giskard_scan.py --target vulnerable`):** `LLMInformationDisclosureDetector` tarafından **1 kritik bulgu** (`3/3` başarısız örnek — parola ve erişim kodu ifşası) tespit edilmiştir (`examples/ornek_giskard_raporu.html`).
- **Güvenli Bot (`python giskard_scan.py --target secure`):** Giskard'ın bağımsız ürettiği 3 gizlilik gereksinimi ve `LLMPromptInjectionDetector` taramasında **0 bulgu** tespit edilmiştir (`examples/ornek_giskard_guvenli_raporu.html`).

### B. İç-Örneklem (In-Sample) Üçlü Ablasyon ve Hakem Doğrulaması (`redteam_benchmark.py`)
`probes.py` içindeki 11 OWASP senaryosu üzerinde üç varyant (`vulnerable`, `secure_no_guard`, `secure_full`) karşılaştırılmıştır:
- **Ayrı ve İhtiyatlı (Fail-Closed) LLM-Hakem (`compliance_judge.py`):** Hedef bot `gemini-3.5-flash-lite` üzerinde çalışırken hakem olarak ayrı bir model (`gemini-3.1-flash-lite`) kullanılmıştır. Hakem, bozuk/eksik JSON çıktılarında iyimser `False` yerine ihtiyatlı **`complied=True` (fail-closed)** döndürür ve denetlenen yanıtı tek-kullanımlık rastgele sınır etiketleriyle ikincil prompt enjeksiyonuna karşı izole eder.
- **İnsan Etiketiyle Hakem Doğrulaması (`validate_judge.py`):** 22 elle etiketlenmiş örnekten (`examples/hakem_etiketli_veri.json` — uydurma parola, yetkisiz rol kabulü ve ikincil hakem enjeksiyonu dahil 11 uyma + 11 reddetme) oluşan doğrulama kümesinde hakem modeli **22/22 (%100.0 uyum, Cohen's κ = 1.0, 0 ayrıştırma hatası)** üretmiştir (`examples/hakem_dogrulama_sonuclari.json`).
- **Bağımsız Olmayan Tekrarlar ve Küme Güven Aralığı:** Tasarım **11 senaryo × 2 tekrar** şeklindedir. Aynı senaryonun tekrarları yüksek korelasyonlu olduğundan 22 bağımsız deney varsaymak güven aralığını yapay biçimde daraltır. Bu nedenle %95 Wilson güven aralıkları **bağımsız senaryo sayısı (`N = 11`)** üzerinden hesaplanmıştır (`0/11` için Wilson üst sınırı **%25.9**, `3/N` kuralıyla **%27.3**).

| Mimari Varyant | Sır Sızıntı Oranı (`N=11` Senaryo ve %95 Wilson GA) | Saldırı İsteğine Uyma — LLM-Hakem (`N=11` Senaryo ve %95 Wilson GA) | Meşru Sorularda Yanlış Engelleme (`N=8`) |
| :--- | :---: | :---: | :---: |
| **1. Zafiyetli (`hr_bot.py`)** | **%81.8** (`9/11` senaryo, GA: `[%52.3, %94.9]`; tekrar: `17/22`) | **%81.8** (`9/11` senaryo, GA: `[%52.3, %94.9]`; tekrar: `18/22`) | %0.0 (`0/8`) |
| **2. Güvenli — Kalkan Kapalı (`enable_input_guard=False`)** | **%0.0** (`0/11` senaryo, GA: `[%0.0, %25.9]`; tekrar: `0/22`) | **%0.0** (`0/11` senaryo, GA: `[%0.0, %25.9]`; tekrar: `0/22`) | %0.0 (`0/8`) |
| **3. Güvenli — Tam Savunma (`enable_input_guard=True`)** | **%0.0** (`0/11` senaryo, GA: `[%0.0, %25.9]`; tekrar: `0/22`) | **%0.0** (`0/11` senaryo, GA: `[%0.0, %25.9]`; tekrar: `0/22`) | %0.0 (`0/8`) |

> **Temel Çıkarım:** `enable_input_guard=False` ile `enable_input_guard=True` koşumlarının birebir aynı sonucu (`0/11`) vermesi, bu senaryo kümesinde regex girdi kalkanının ölçülebilir ek bir güvenlik katkısı sağlamadığını; asıl korumayı **sırsız bağlam + veri sınırlandırma + model dışı RBAC** mimarisinin üstlendiğini somut olarak gösterir.

---

## 3. OWASP Top 10 for LLM Applications (2025) Eşleştirmesi

| OWASP Risk Kategorisi | Zafiyetli Sürümdeki Kök Neden (`hr_bot.py`) | Güvenli Sürümdeki Çözüm (`hr_bot_guvenli.py` & `main.py`) |
| :--- | :--- | :--- |
| **LLM01: Prompt Injection** | Kullanıcı girdisi, konuşma geçmişi ve sistem talimatları arasında izolasyon bulunmaması. | Sunucu taraflı oturum (`ServerSessionStore`), `<kullanici_mesaji>` sınırlandırması ve geçmiş hijyeni (`_sanitize_history`). |
| **LLM02: Sensitive Information Disclosure** | Veritabanı şifresi, bypass kodu ve CEO maaşının sistem promptuna yazılması; yetki beyanına güvenilmesi. | Sırların LLM bağlamından çıkarılması, hız sınırlı `GET /api/admin/audit-records` model dışı RBAC doğrulaması ve çıktı DLP kontrolü. |
| **LLM07: System Prompt Leakage** | Sistem talimatlarının aynen tekrarlanmasına karşı koruma ve izleme bulunmaması. | Genel sınır ilkeleri ve çıktı DLP katmanında izlenen sıfır-yetkili canary belirteci (`CANARY-HR-GUARD-9482`). |

---

## 4. Proje Yapısı

```text
zafiyetli-ik-asistani/
├── config.py                   # Ortam değişkenleri ve uygulama ayarları (tek doğruluk kaynağı)
├── llm_core.py                 # Paylaşılan Gemini istemcisi (25 sn zaman aşımlı) ve tipli istisnalar
├── hr_bot.py                   # Kasıtlı olarak zafiyetli İK asistanı
├── hr_bot_guvenli.py           # Savunmalı İK asistanı ve model dışı RBAC servisi
├── leak_detector.py            # Çok katmanlı sızıntı (DLP/Canary/Base64/Regex) ve yardımcı ön-filtre
├── compliance_judge.py         # Ayrı, fail-closed, ikincil enjeksiyon korumalı LLM-hakem ve Kappa/Wilson hesabı
├── validate_judge.py           # 22 insan etiketli örnek üzerinde hakem uyum doğrulama aracı
├── probes.py                   # 11 OWASP saldırı senaryosu, 8 negatif kontrol ve tohum veri seti
├── giskard_gemini_client.py    # Giskard LLMClient arayüzünün Google Gemini adaptörü
├── giskard_scan.py             # Gerçek giskard.scan() otomatik zafiyet tarama betiği
├── redteam_benchmark.py        # 3 varyantlı ablasyon ve N=11 küme istatistikli kıyaslama aracı
├── main.py                     # Sunucu oturumlu, RBAC, sağdan XFF ve sandbox CSP korumalı FastAPI sunucusu
├── static/                     # Harici CDN gerektirmeyen, XSS korumalı web arayüzü
├── tests/                      # 49 testlik birim, API, oturum, XFF/proxy ve canlı entegrasyon paketi
├── examples/                   # Zafiyetli/güvenli Giskard HTML çıktıları, kıyaslama ve hakem doğrulama JSON verileri
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
- **Giskard Otomatik Tarayıcısı (`requirements-scan.txt`):** **Python 3.10 veya 3.11** (`giskard==2.19.2` paketinin `scipy<1.12.0` ve `numpy<2.0` sabitleri nedeniyle Python 3.12+ ortamında kurulmamalıdır; CI matrisi bu ayrımı zorunlu kılar).
- Google AI Studio üzerinden alınmış bir `GEMINI_API_KEY`.

### Windows (PowerShell) Kurulumu
```powershell
git clone https://github.com/mehmeteminyilmaz/zafiyetli-ik-asistani.git
cd zafiyetli-ik-asistani

py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1

pip install -r requirements.txt
pip install -r requirements-scan.txt  # İsteğe bağlı: Giskard tarayıcısı (Python 3.10/3.11)
Copy-Item .env.example .env
```

### Linux ve macOS (Bash) Kurulumu
```bash
git clone https://github.com/mehmeteminyilmaz/zafiyetli-ik-asistani.git
cd zafiyetli-ik-asistani

python3.11 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
pip install -r requirements-scan.txt  # İsteğe bağlı: Giskard tarayıcısı (Python 3.10/3.11)
cp .env.example .env
chmod +x calistir.sh
```

### Çalıştırma, Doğrulama ve Test Komutları
```bash
# Tek süreç (single-worker) web sunucusunu başlatma (http://127.0.0.1:8000):
python main.py

# Dış-örneklem gerçek Giskard taraması (zafiyetli ve güvenli hedef):
python giskard_scan.py --target vulnerable
python giskard_scan.py --target secure

# Hakem modelinin insan etiketli küme üzerinde uyum doğrulaması:
python validate_judge.py

# Üçlü ablasyon ve N=11 küme istatistikli kıyaslama testi:
python redteam_benchmark.py --runs 2

# Birim/API testleri ve statik analiz:
pip install -r requirements-dev.txt
pytest -v
ruff check .
```

---

## 6. Bilinen Sınırlamalar ve Operasyonel Notlar

1. **İç-Örneklem (In-Sample) Yanlılığı ve Küçük Örneklem:** `probes.py` içindeki 11 senaryo, savunma mimarisini geliştiren aynı ekip tarafından yazılmıştır (*in-sample*). Güvenli sistem promptu özel probe kelimelerinden arındırılmış ve ek olarak dış-örneklem `giskard.scan(--target secure)` çalıştırılmış olsa da, `0/11` sonucu %95 güven düzeyinde **`[%0.0, %25.9]`** gibi geniş bir aralığa karşılık gelir; görünmeyen yeni saldırı sınıflarında %0 garanti edilemez.
2. **Tekrarların Bağımlılığı:** Düşük sıcaklıkta (`0.2`) aynı senaryonun tekrarları birbirine bağlıdır; tekrar sayısını (`--runs`) artırmak yalnızca aynı prompt üzerindeki varyansı ölçer, etkin örneklem boyutunu (`N=11`) büyütmez. Güven aralığını daraltmak için birbirinden bağımsız yeni senaryolar eklenmelidir.
3. **Aynı Sağlayıcı Ailesinden Hakem Modeli:** Hedef bot (`gemini-3.5-flash-lite`) ile hakem model (`gemini-3.1-flash-lite`) farklı modeller olsa da aynı üretici ailesine (Google Gemini) aittir ve ortak kör noktaları paylaşabilir. Üretim düzeyinde değerlendirmelerde farklı model ailelerinden (ör. Claude veya GPT) çapraz hakem kullanılması önerilir.
4. **Süreç İçi Bellek (Single-Worker Varsayımı):** `ServerSessionStore` ve `SlidingWindowRateLimiter` süreç içi bellekte tutulur. `uvicorn` birden fazla işçi süreçle (`--workers > 1`) çalıştırılırsa oturum geçmişi süreçler arasında paylaşılmaz ve hız sınırı sayaçları bölünür; çoklu worker ortamında Redis benzeri harici bir depo gerekir.
5. **Ters Vekil Sunucu (Reverse Proxy) Davranışı:** Varsayılan `TRUST_PROXY_HEADERS=false` ayarında uygulama bir reverse proxy arkasına konulursa tüm istemciler hız sınırlayıcıya proxy'nin tek IP adresi olarak görünür ve `/api/run-scan` için `SCAN_TOKEN` zorunlu hale gelir. `TRUST_PROXY_HEADERS=true` açıldığında ise sahte `X-Forwarded-For` başlıklarına kanmamak için `TRUSTED_PROXY_COUNT` değeri öndeki güvenilir proxy sayısına eşitlenmelidir (IP sağdan okunur).

---

## 7. Lisans

Bu proje [MIT Lisansı](LICENSE) altında lisanslanmıştır.

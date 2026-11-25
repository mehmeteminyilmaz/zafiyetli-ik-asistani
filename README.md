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

Tek bir test yönteminin yanlılığını önlemek amacıyla **dış-örneklem (out-of-sample) otomatik tarama**, **iç-örneklem (in-sample) ablasyon testi** ve **çok turlu uyarlanabilir kırmızı takım saldırısı** birlikte yürütülmüştür:

### A. Dış-Örneklem Otomatik Giskard Taraması (`giskard_scan.py`)
Proje yazarlarının yazdığı saldırı cümlelerinden bağımsız olarak, `giskard.scan()` kendi güvenlik gereksinimlerini ve Türkçe çekişmeli saldırı girdilerini otomatik sentezler (`giskard_gemini_client.py` adaptörü üzerinden). Herhangi bir dedektör hatasının sessizce "0 bulgu" sayılmasını önlemek için `raise_exceptions=True` zorunlu kılınmış ve test edilen gerçek hedef girdi sayısı telemetriyle (`examples/giskard_tarama_ozeti.json`) kaydedilmiştir:
- **Zafiyetli Bot (`python giskard_scan.py --target vulnerable`):** 4 güvenlik gereksinimi × 3 örnek + 6 prompt injection girdisi olmak üzere **18 çekişmeli girdi** 10 ayrı partide test edilmiştir. `LLMInformationDisclosureDetector` tarafından **3 ayrı kritik bulgu** (veritabanı parolası, acil kod ve kişisel veri ifşası) tespit edilmiştir (`examples/ornek_giskard_raporu.html`).
- **Güvenli Bot (`python giskard_scan.py --target secure`):** 5 güvenlik gereksinimi × 4 örnek + 8 prompt injection girdisi olmak üzere **28 çekişmeli girdi** 9 ayrı partide test edilmiştir. Hem bilgi ifşası hem de prompt injection dedektörlerinde **0 bulgu** kaydedilmiştir (`examples/ornek_giskard_guvenli_raporu.html`).
- **Metodolojik Uyarı:** Giskard'ın gereksinim üreticisi ve değerlendiricisi olarak Google Gemini model ailesi kullanılmıştır. Senaryolar yazar kurgusundan bağımsız sentezlense de hedef bot ile aynı üretici ailesini paylaştığından ortak kör nokta riski mevcuttur; ayrıca 28 denemede 0 bulgu elde edilmesi modelin matematiksel olarak kırılmaz olduğunu kanıtlamaz.

### B. İç-Örneklem Üçlü Ablasyon ve Hakem Doğrulaması (`redteam_benchmark.py`)
`probes.py` içindeki 11 OWASP senaryosu üzerinde üç varyant (`vulnerable`, `secure_no_guard`, `secure_full`) karşılaştırılmıştır:
- **Ayrı ve İhtiyatlı (Fail-Closed) LLM-Hakem (`compliance_judge.py`):** Hedef bot `gemini-3.5-flash-lite` üzerinde çalışırken hakem olarak ayrı bir model (`gemini-3.1-flash-lite`) kullanılmıştır. Hakem, bozuk/eksik JSON çıktılarında iyimser `False` yerine ihtiyatlı **`complied=True` (fail-closed)** döndürür ve denetlenen yanıtı tek-kullanımlık rastgele sınır etiketleriyle ikincil prompt enjeksiyonuna karşı izole eder. Kıyaslama koşumunda hakem ayrıştırma hatası toplamı `judge_parse_error_total: 0` olarak gerçekleşmiştir.
- **Sınır Vakaları ve Gerçek Çıktılarla Hakem Doğrulaması (`validate_judge.py`):** Hakem modelinin güvenilirliği, 15'i canlı bot çıktısı (`hr_bot.py` ve `hr_bot_guvenli.py`) ve 10'u zor sınır vakası (kısmi ipucu, empatik ret, imalı sızıntı, ikincil hakem enjeksiyonu) olmak üzere **25 örnekten** oluşan kümede (`examples/hakem_etiketli_veri.json`; 10 uyma, 15 reddetme) test edilmiştir. Hakem modeli **25/25 (%100.0 uyum, Cohen's κ = 1.0, 0 ayrıştırma hatası)** üretmiştir (`examples/hakem_dogrulama_sonuclari.json`).
  - *İstatistiksel Aralıklar:* %100 uyumun %95 Wilson güven aralığı **`[%86.7, %100.0]`** (Duyarlılık: `[%72.2, %100.0]`, Özgüllük: `[%79.6, %100.0]`) olarak hesaplanmıştır.
  - *Tek-Etiketleyici Kısıtı:* Etiketler proje yazarı tarafından atanmıştır (`single_author_rater`). Bağımsız ikinci bir insan etiketleyici bulunmadığından etiketleyiciler arası güvenilirlik katsayısı (inter-rater κ) ölçülememiştir.
- **Senaryo Toplulaştırma Kuralı ve Küme Güven Aralığı:** Tasarım **11 senaryo × 2 tekrar** şeklindedir. Bir senaryonun tekrarları bağımsız olmadığından toplulaştırma kuralı olarak **"en az bir tekrarda etkilenme (any-hit across repeats)"** uygulanmıştır (bir senaryonun 2 tekrarından en az 1'inde sızıntı/uyma olursa o senaryo etkilenmiş sayılır). Bu kural zafiyetli botta aralıklı sızıntıları (`P11`: 1/2 tekrar -> 1/1 senaryo) yakalarken, güvenli bot için `0/11` standardını daha sıkı hale getirir. %95 Wilson güven aralıkları **bağımsız senaryo sayısı (`N = 11`)** üzerinden raporlanmıştır (`0/11` için Wilson üst sınırı **%25.9**, `3/N` kuralıyla **%27.3**).

| Mimari Varyant | Sır Sızıntı Oranı (`N=11` Senaryo ve %95 Wilson GA) | Saldırı İsteğine Uyma — LLM-Hakem (`N=11` Senaryo ve %95 Wilson GA) | Meşru Sorularda Yanlış Engelleme (`N=8`) |
| :--- | :---: | :---: | :---: |
| **1. Zafiyetli (`hr_bot.py`)** | **%81.8** (`9/11` senaryo, GA: `[%52.3, %94.9]`; tekrar: `17/22`) | **%81.8** (`9/11` senaryo, GA: `[%52.3, %94.9]`; tekrar: `18/22`) | %0.0 (`0/8`) |
| **2. Güvenli — Kalkan Kapalı (`enable_input_guard=False`)** | **%0.0** (`0/11` senaryo, GA: `[%0.0, %25.9]`; tekrar: `0/22`) | **%0.0** (`0/11` senaryo, GA: `[%0.0, %25.9]`; tekrar: `0/22`) | %0.0 (`0/8`) |
| **3. Güvenli — Tam Savunma (`enable_input_guard=True`)** | **%0.0** (`0/11` senaryo, GA: `[%0.0, %25.9]`; tekrar: `0/22`) | **%0.0** (`0/11` senaryo, GA: `[%0.0, %25.9]`; tekrar: `0/22`) | %0.0 (`0/8`) |

> **Temel Çıkarım:** `enable_input_guard=False` ile `enable_input_guard=True` koşumlarının birebir aynı sonucu (`0/11`) vermesi, bu senaryo kümesinde regex girdi kalkanının ölçülebilir ek bir güvenlik katkısı sağlamadığını; asıl korumayı **sırsız bağlam + veri sınırlandırma + model dışı RBAC** mimarisinin üstlendiğini somut olarak gösterir.

### C. Çok Turlu Uyarlanabilir (Adaptive) Kırmızı Takım Saldırısı (`adaptive_redteam.py`)
Statik probe listelerinin ötesine geçmek amacıyla, saldırgan tarafında hedef botun iç yönergesini bilmeyen, botun her turdaki yanıtına göre taktiğini dinamik değiştiren (`temperature=0.7`) bağımsız bir saldırgan LLM kullanılmıştır (`3 kampanya × 3 konuşma turu`):
- **Zafiyetli Bot:** Saldırgan LLM 3 kampanyanın tamamında (`3/3`, **%100.0**, %95 Wilson GA: **`[%43.9, %100.0]`**) asistanı manipüle ederek sır sızıntısı ve uyma elde etmiştir (`examples/uyarlanabilir_saldiri_sonuclari.json`).
- **Güvenli Bot (Kalkan Kapalı ve Tam Savunma):** Saldırgan LLM her turda taktik değiştirmesine (dolaylı dilekçe özetleme, JSON şablon zorlama, çok adımlı bağlam kurma) rağmen 3 kampanyanın hiçbirinde (`0/3`, **%0.0**, %95 Wilson GA: **`[%0.0, %56.1]`**) başarıya ulaşamamıştır.

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
├── llm_core.py                 # Paylaşılan Gemini istemcisi (60 sn zaman aşımlı) ve tipli istisnalar
├── hr_bot.py                   # Kasıtlı olarak zafiyetli İK asistanı
├── hr_bot_guvenli.py           # Savunmalı İK asistanı ve model dışı RBAC servisi
├── leak_detector.py            # Çok katmanlı sızıntı (DLP/Canary/Base64/Regex) ve yardımcı ön-filtre
├── compliance_judge.py         # Ayrı, fail-closed, ikincil enjeksiyon korumalı LLM-hakem ve Kappa/Wilson hesabı
├── validate_judge.py           # 25 gerçek ve sınır vakalı örnek üzerinde hakem doğrulama aracı
├── adaptive_redteam.py         # Çok turlu uyarlanabilir (adaptive) LLM kırmızı takım saldırı aracı
├── probes.py                   # 11 OWASP saldırı senaryosu, 8 negatif kontrol ve tohum veri seti
├── giskard_gemini_client.py    # Giskard LLMClient arayüzünün Google Gemini adaptörü (çapraz havuz yedekli)
├── giskard_scan.py             # Gerçek giskard.scan() otomatik zafiyet tarama betiği (telemetri kayıtlı)
├── redteam_benchmark.py        # 3 varyantlı ablasyon ve N=11 küme istatistikli kıyaslama aracı
├── main.py                     # Sunucu oturumlu, RBAC, sağdan XFF ve sandbox CSP korumalı FastAPI sunucusu
├── static/                     # Harici CDN gerektirmeyen, XSS korumalı web arayüzü
├── tests/                      # 52 testlik birim, API, oturum, XFF/proxy ve canlı entegrasyon paketi
├── examples/                   # Giskard HTML raporları, kıyaslama, hakem doğrulama ve uyarlanabilir saldırı JSON verileri
├── docs/                       # Mimari karşılaştırma şeması
├── requirements.txt            # Hafif sohbet sunucusu bağımlılıkları (Python 3.10 - 3.12)
├── requirements-scan.txt       # Giskard tarama bağımlılıkları (Python 3.10 - 3.11)
├── requirements-dev.txt        # Test (pytest) ve statik analiz (ruff) bağımlılıkları
├── .github/workflows/ci.yml    # Çekirdek (3.10-3.12) ve Giskard (3.10-3.11) ayrık CI matrisi
├── calistir.bat / calistir.sh  # Windows ve Linux/macOS başlatma betikleri
├── Makefile                    # Standart geliştirme, test ve denetim hedefleri
└── LICENSE                     # MIT Lisansı
```

---

## 5. Kurulum ve Çalıştırma

### Ön Koşullar
- **Sohbet Sunucusu, Kıyaslama ve Testler (`requirements.txt`):** Python 3.10, 3.11 veya 3.12
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

# Hakem modelinin 25 sınır vakalı veri üzerinde uyum doğrulaması:
python validate_judge.py

# Üçlü ablasyon ve N=11 küme istatistikli kıyaslama testi:
python redteam_benchmark.py --runs 2

# Çok turlu uyarlanabilir (adaptive) LLM saldırı testi:
python adaptive_redteam.py --turns 3

# Birim/API testleri ve statik analiz:
pip install -r requirements-dev.txt
pytest -v
ruff check .
```

---

## 6. Bilinen Sınırlamalar ve Operasyonel Notlar

1. **İç-Örneklem (In-Sample) Yanlılığı ve Küçük Örneklem:** `probes.py` içindeki 11 senaryo, savunma mimarisini geliştiren aynı ekip tarafından yazılmıştır (*in-sample*). Güvenli sistem promptu özel probe kelimelerinden arındırılmış ve ek olarak dış-örneklem `giskard.scan(--target secure)` çalıştırılmış olsa da, `0/11` sonucu %95 güven düzeyinde **`[%0.0, %25.9]`** gibi bir aralığa karşılık gelir; görünmeyen yeni saldırı sınıflarında mutlak %0 garanti edilemez.
2. **Tek-Etiketleyici Kısıtı:** Hakem kalibrasyon veri setindeki (`examples/hakem_etiketli_veri.json`) etiketler proje yazarı tarafından atanmıştır (`single_author_rater`). İkinci bir bağımsız insan etiketleyici bulunmadığından etiketleyiciler arası güvenilirlik (inter-rater agreement) ölçülmemiştir.
3. **Tekrarların Bağımlılığı ve Toplulaştırma:** Düşük sıcaklıkta aynı senaryonun tekrarları birbirine bağlıdır; tekrar sayısını artırmak etkin örneklem boyutunu (`N=11`) büyütmez. Bu nedenle toplulaştırma kuralı olarak senaryo bazlı *en az bir tekrarda etkilenme* esası benimsenmiştir.
4. **Aynı Sağlayıcı Ailesinden Hakem ve Tarayıcı Modelleri:** Hedef bot (`gemini-3.5-flash-lite`), hakem model (`gemini-3.1-flash-lite`) ve Giskard değerlendiricisi farklı modeller olsa da aynı üretici ailesine (Google Gemini) aittir ve ortak kör noktaları paylaşabilir. Üretim düzeyinde bağımsız denetimlerde farklı model ailelerinden (ör. Claude veya GPT) çapraz hakem kullanılması önerilir.
5. **Süreç İçi Bellek (Single-Worker Varsayımı):** `ServerSessionStore` ve `SlidingWindowRateLimiter` süreç içi bellekte tutulur. `uvicorn` birden fazla işçi süreçle (`--workers > 1`) çalıştırılırsa oturum geçmişi süreçler arasında paylaşılmaz ve hız sınırı sayaçları bölünür; çoklu worker ortamında Redis benzeri harici bir depo gerekir.
6. **Ters Vekil Sunucu (Reverse Proxy) Davranışı:** Varsayılan `TRUST_PROXY_HEADERS=false` ayarında uygulama bir reverse proxy arkasına konulursa tüm istemciler hız sınırlayıcıya proxy'nin tek IP adresi olarak görünür ve `/api/run-scan` için `SCAN_TOKEN` zorunlu hale gelir. `TRUST_PROXY_HEADERS=true` açıldığında ise sahte `X-Forwarded-For` başlıklarına kanmamak için `TRUSTED_PROXY_COUNT` değeri öndeki güvenilir proxy sayısına eşitlenmelidir (IP sağdan okunur).

---

## 7. Lisans

Bu proje [MIT Lisansı](LICENSE) altında lisanslanmıştır.

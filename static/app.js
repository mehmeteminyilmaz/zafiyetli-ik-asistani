/**
 * TechCorp İK Asistanı İstemci Uygulaması
 * - XSS Korumalı: Kullanıcı ve bot çıktıları asla innerHTML ile eklenmez;
 *   yalnızca createElement + createTextNode kullanılır.
 * - Çok turlu konuşma geçmişi (chatHistory) desteklenir.
 * - Zafiyetli / Güvenli mod geçişi, canlı /health kontrolü ve HTTP durum doğrulaması içerir.
 */
(function () {
  "use strict";

  const CONTENT = window.UI_CONTENT;

  let currentMode = "vulnerable";
  let chatHistory = [];
  let scanPollTimer = null;

  // DOM Referansları
  const chatMessages = document.getElementById("chat-messages");
  const chatForm = document.getElementById("chat-form");
  const userInput = document.getElementById("user-input");
  const btnSend = document.getElementById("btn-send");
  const btnReset = document.getElementById("btn-reset");
  const btnModeVuln = document.getElementById("btn-mode-vulnerable");
  const btnModeSecure = document.getElementById("btn-mode-secure");
  const modeBanner = document.getElementById("mode-banner");
  const modeBannerText = document.getElementById("mode-banner-text");
  const shortcutContainer = document.getElementById("shortcut-buttons");
  const healthBadge = document.getElementById("health-badge");
  const healthText = document.getElementById("health-text");
  const btnScan = document.getElementById("btn-scan");
  const scanText = document.getElementById("scan-text");
  const scanBar = document.getElementById("scan-bar");
  const scanStatusText = document.getElementById("scan-status-text");
  const btnBenchmark = document.getElementById("btn-benchmark");
  const benchModal = document.getElementById("benchmark-modal");
  const btnCloseModal = document.getElementById("btn-close-modal");
  const benchModalBody = document.getElementById("benchmark-modal-body");

  /**
   * Çok satırlı metni XSS riski olmadan güvenli DOM düğümleri olarak ekler.
   */
  function appendSafeMultilineText(container, text) {
    const lines = String(text ?? "").split("\n");
    lines.forEach((line, idx) => {
      container.appendChild(document.createTextNode(line));
      if (idx < lines.length - 1) {
        container.appendChild(document.createElement("br"));
      }
    });
  }

  function createAvatar(sender) {
    const avatar = document.createElement("div");
    avatar.className = `avatar ${sender === "user" ? "user" : "bot"}`;
    avatar.setAttribute("aria-hidden", "true");
    avatar.textContent = sender === "user" ? "SN" : "İK";
    return avatar;
  }

  function appendMessage(sender, text, options = {}) {
    const {
      isLeak = false,
      leakedCategories = [],
      guardBlocked = false,
      triggeredRules = [],
      isError = false,
    } = options;

    const isUser = sender === "user";
    const row = document.createElement("div");
    row.className = `msg-row ${isUser ? "user" : "bot"}`;

    const bubble = document.createElement("div");
    bubble.className = `bubble ${isUser ? "user" : "bot"}${isError ? " error" : ""}`;

    if (!isUser) {
      const senderP = document.createElement("p");
      senderP.className = "sender-label";
      senderP.textContent = CONTENT.botSenderName;
      bubble.appendChild(senderP);
    }

    const bodyDiv = document.createElement("div");
    appendSafeMultilineText(bodyDiv, text);
    bubble.appendChild(bodyDiv);

    if (isLeak) {
      const alertBox = document.createElement("div");
      alertBox.className = "security-alert leak";
      alertBox.setAttribute("role", "alert");
      const detail = leakedCategories.length ? ` (${leakedCategories.join(", ")})` : "";
      alertBox.textContent = `${CONTENT.alerts.leakDetected}${detail}`;
      bubble.appendChild(alertBox);
    } else if (guardBlocked) {
      const guardBox = document.createElement("div");
      guardBox.className = "security-alert blocked";
      guardBox.setAttribute("role", "status");
      const ruleText = triggeredRules.length ? ` [${triggeredRules.join(", ")}]` : "";
      guardBox.textContent = `${CONTENT.alerts.guardBlocked}${ruleText}`;
      bubble.appendChild(guardBox);
    }

    row.appendChild(createAvatar(sender));
    row.appendChild(bubble);
    chatMessages.appendChild(row);
    chatMessages.scrollTop = chatMessages.scrollHeight;
  }

  function resetConversation() {
    chatHistory = [];
    while (chatMessages.firstChild) {
      chatMessages.removeChild(chatMessages.firstChild);
    }
    const welcome =
      currentMode === "vulnerable" ? CONTENT.welcomeVulnerable : CONTENT.welcomeSecure;
    appendMessage("bot", welcome);
  }

  function setMode(mode) {
    if (mode !== "vulnerable" && mode !== "secure") return;
    currentMode = mode;

    const isVuln = mode === "vulnerable";
    btnModeVuln.className = `mode-btn ${isVuln ? "active-vulnerable" : ""}`;
    btnModeSecure.className = `mode-btn ${!isVuln ? "active-secure" : ""}`;
    btnModeVuln.setAttribute("aria-pressed", String(isVuln));
    btnModeSecure.setAttribute("aria-pressed", String(!isVuln));

    modeBanner.className = `mode-banner ${mode}`;
    modeBannerText.textContent = CONTENT.modeDescriptions[mode];
    resetConversation();
  }

  function renderShortcuts() {
    CONTENT.presets.forEach((preset) => {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = `chip-btn${preset.isAttack ? " attack" : ""}`;
      btn.textContent = preset.label;
      btn.setAttribute("aria-label", preset.label);
      btn.addEventListener("click", () => {
        userInput.value = preset.prompt;
        userInput.focus();
      });
      shortcutContainer.appendChild(btn);
    });
  }

  async function refreshHealth() {
    try {
      const res = await fetch("/health", { cache: "no-store" });
      if (!res.ok) throw new Error("Health check failed");
      const data = await res.json();
      if (data.status === "ok") {
        healthBadge.className = "health-badge online";
        healthText.textContent = `${CONTENT.healthLabels.online} (${data.model})`;
      } else {
        healthBadge.className = "health-badge degraded";
        healthText.textContent = CONTENT.healthLabels.degraded;
      }
    } catch (_err) {
      healthBadge.className = "health-badge offline";
      healthText.textContent = CONTENT.healthLabels.offline;
    }
  }

  async function handleSendMessage(event) {
    event.preventDefault();
    const message = userInput.value.trim();
    if (!message) return;

    appendMessage("user", message);
    userInput.value = "";
    userInput.disabled = true;
    btnSend.disabled = true;

    const loadingRow = document.createElement("div");
    loadingRow.className = "msg-row bot";
    const loadingBubble = document.createElement("div");
    loadingBubble.className = "bubble bot";
    loadingBubble.textContent = "Yanıt hazırlanıyor...";
    loadingRow.appendChild(createAvatar("bot"));
    loadingRow.appendChild(loadingBubble);
    chatMessages.appendChild(loadingRow);
    chatMessages.scrollTop = chatMessages.scrollHeight;

    try {
      const response = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message,
          mode: currentMode,
          history: chatHistory,
        }),
      });

      let payload = null;
      try {
        payload = await response.json();
      } catch (_parseErr) {
        payload = null;
      }

      loadingRow.remove();

      if (!response.ok) {
        const errDetail =
          (payload && typeof payload.detail === "string" && payload.detail) ||
          `İstek başarısız oldu (HTTP ${response.status}).`;
        appendMessage("bot", errDetail, { isError: true });
        return;
      }

      const replyText = payload.reply || "";
      chatHistory.push({ role: "user", content: message });
      chatHistory.push({ role: "model", content: replyText });
      if (chatHistory.length > 20) {
        chatHistory = chatHistory.slice(-20);
      }

      appendMessage("bot", replyText, {
        isLeak: Boolean(payload.is_leak),
        leakedCategories: Array.isArray(payload.leaked_categories) ? payload.leaked_categories : [],
        guardBlocked: Boolean(payload.guard_blocked),
        triggeredRules: Array.isArray(payload.triggered_rules) ? payload.triggered_rules : [],
      });
    } catch (_netErr) {
      loadingRow.remove();
      appendMessage("bot", "Sunucuya ulaşılamadı. Bağlantınızı kontrol edin.", { isError: true });
    } finally {
      userInput.disabled = false;
      btnSend.disabled = false;
      userInput.focus();
    }
  }

  async function triggerScan() {
    btnScan.disabled = true;
    scanText.textContent = "Tarama Sürüyor...";
    scanBar.classList.remove("hidden");
    scanStatusText.textContent = `Giskard taraması başlatılıyor (${currentMode})...`;

    try {
      const res = await fetch("/api/run-scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: currentMode }),
      });
      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        const msg = (data && data.detail) || `Tarama başlatılamadı (HTTP ${res.status}).`;
        scanStatusText.textContent = msg;
        btnScan.disabled = false;
        scanText.textContent = "Giskard Taraması Başlat";
        return;
      }

      scanStatusText.textContent = data.message || "Tarama devam ediyor...";

      if (scanPollTimer) clearInterval(scanPollTimer);
      scanPollTimer = setInterval(async () => {
        try {
          const sRes = await fetch("/api/scan-status", { cache: "no-store" });
          if (!sRes.ok) return;
          const sData = await sRes.json();
          scanStatusText.textContent = sData.last_result;

          if (!sData.is_running) {
            clearInterval(scanPollTimer);
            scanPollTimer = null;
            btnScan.disabled = false;
            scanText.textContent = "Giskard Taraması Başlat";
            if (sData.completed && !sData.failed) {
              window.open("/report", "_blank", "noopener");
            }
          }
        } catch (_pollErr) {
          clearInterval(scanPollTimer);
          scanPollTimer = null;
          btnScan.disabled = false;
          scanText.textContent = "Giskard Taraması Başlat";
        }
      }, 3000);
    } catch (_err) {
      scanStatusText.textContent = "Sunucuya bağlanılamadı.";
      btnScan.disabled = false;
      scanText.textContent = "Giskard Taraması Başlat";
    }
  }

  function buildBenchmarkDom(data) {
    while (benchModalBody.firstChild) {
      benchModalBody.removeChild(benchModalBody.firstChild);
    }

    const summaryP = document.createElement("p");
    summaryP.textContent =
      `Model: ${data.model} | Probe Tekrarı (N): ${data.runs_per_probe} | ` +
      `Zafiyetli Bot Genel ASR: %${data.vulnerable_overall_asr_pct} -> ` +
      `Güvenli Bot Genel ASR: %${data.secure_overall_asr_pct} | ` +
      `Yanlış Alarm Oranı (FPR): %${data.secure_false_positive_rate_pct}`;
    summaryP.style.fontWeight = "600";
    benchModalBody.appendChild(summaryP);

    const table = document.createElement("table");
    table.className = "bench-table";

    const thead = document.createElement("thead");
    const headRow = document.createElement("tr");
    ["Kod", "Saldırı Senaryosu", "OWASP Kategorisi", "Zafiyetli ASR", "Güvenli ASR"].forEach(
      (col) => {
        const th = document.createElement("th");
        th.textContent = col;
        headRow.appendChild(th);
      }
    );
    thead.appendChild(headRow);
    table.appendChild(thead);

    const tbody = document.createElement("tbody");
    (data.probes || []).forEach((probe) => {
      const tr = document.createElement("tr");
      [
        probe.probe_id,
        probe.title,
        probe.owasp_category,
        `%${probe.vulnerable_asr_pct} (${probe.vulnerable_leaks}/${probe.runs})`,
        `%${probe.secure_asr_pct} (${probe.secure_leaks}/${probe.runs})`,
      ].forEach((val) => {
        const td = document.createElement("td");
        td.textContent = String(val);
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    benchModalBody.appendChild(table);
  }

  async function openBenchmarkModal() {
    benchModal.classList.remove("hidden");
    while (benchModalBody.firstChild) {
      benchModalBody.removeChild(benchModalBody.firstChild);
    }
    benchModalBody.appendChild(document.createTextNode("Kıyaslama sonuçları yükleniyor..."));

    try {
      const res = await fetch("/api/benchmark", { cache: "no-store" });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        benchModalBody.textContent =
          data.detail || "Kıyaslama verisi bulunamadı (`python redteam_benchmark.py` çalıştırın).";
        return;
      }
      buildBenchmarkDom(data);
    } catch (_err) {
      benchModalBody.textContent = "Kıyaslama verisi alınırken ağ hatası oluştu.";
    }
  }

  function closeBenchmarkModal() {
    benchModal.classList.add("hidden");
  }

  // Olay Dinleyicileri
  chatForm.addEventListener("submit", handleSendMessage);
  btnReset.addEventListener("click", resetConversation);
  btnModeVuln.addEventListener("click", () => setMode("vulnerable"));
  btnModeSecure.addEventListener("click", () => setMode("secure"));
  btnScan.addEventListener("click", triggerScan);
  btnBenchmark.addEventListener("click", openBenchmarkModal);
  btnCloseModal.addEventListener("click", closeBenchmarkModal);
  benchModal.addEventListener("click", (e) => {
    if (e.target === benchModal) closeBenchmarkModal();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !benchModal.classList.contains("hidden")) {
      closeBenchmarkModal();
    }
  });

  // İlk Yükleme
  renderShortcuts();
  setMode("vulnerable");
  refreshHealth();
  setInterval(refreshHealth, 30000);
})();

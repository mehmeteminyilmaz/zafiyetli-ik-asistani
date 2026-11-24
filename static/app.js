/**
 * TechCorp İK Asistanı İstemci Uygulaması
 * - XSS Korumalı: Kullanıcı ve bot çıktıları asla innerHTML ile eklenmez;
 *   yalnızca createElement + createTextNode kullanılır.
 * - Sunucu Taraflı Oturum: Konuşma geçmişi istemciden gönderilmez (history poisoning önlemi);
 *   yalnızca sunucunun ürettiği `session_id` korunur ve sıfırlamada `/api/chat/reset` çağrılır.
 */
(function () {
  "use strict";

  const CONTENT = window.UI_CONTENT;

  let currentMode = "vulnerable";
  let currentSessionId = null;
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

  async function resetConversation() {
    const oldSession = currentSessionId;
    currentSessionId = null;
    if (oldSession) {
      fetch("/api/chat/reset", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ session_id: oldSession }),
      }).catch(() => {});
    }

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
          session_id: currentSessionId,
        }),
      });

      const payload = await response.json().catch(() => null);
      loadingRow.remove();

      if (!response.ok || !payload) {
        const errDetail =
          (payload && typeof payload.detail === "string" && payload.detail) ||
          `İstek başarısız oldu (HTTP ${response.status}).`;
        appendMessage("bot", errDetail, { isError: true });
        return;
      }

      currentSessionId = payload.session_id || currentSessionId;
      appendMessage("bot", payload.reply || "", {
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

  function formatStat(statObj) {
    if (!statObj) return "-";
    if (statObj.scenario_wilson_95_ci_pct) {
      const ci = statObj.scenario_wilson_95_ci_pct;
      return (
        `%${statObj.scenario_rate_pct} (${statObj.affected_scenarios}/${statObj.total_scenarios} senaryo, ` +
        `%95 GA: [%${ci[0]}, %${ci[1]}])`
      );
    }
    const ci = statObj.wilson_95_ci_pct || [0, 0];
    return `%${statObj.rate_pct} (${statObj.count}/${statObj.total}, %95 GA: [%${ci[0]}, %${ci[1]}])`;
  }

  function buildBenchmarkDom(data) {
    while (benchModalBody.firstChild) {
      benchModalBody.removeChild(benchModalBody.firstChild);
    }

    if (data.methodology_note) {
      const noteP = document.createElement("p");
      noteP.textContent = data.methodology_note;
      benchModalBody.appendChild(noteP);
    }

    if (data.variants) {
      const summaryTable = document.createElement("table");
      summaryTable.className = "bench-table";
      const sHead = document.createElement("thead");
      const sHr = document.createElement("tr");
      ["Mimari Varyant", "Sır Sızıntı Oranı (Leak)", "Saldırı İsteğine Uyma (LLM-Hakem)"].forEach((c) => {
        const th = document.createElement("th");
        th.textContent = c;
        sHr.appendChild(th);
      });
      sHead.appendChild(sHr);
      summaryTable.appendChild(sHead);

      const sBody = document.createElement("tbody");
      [
        ["1. Zafiyetli (hr_bot.py)", data.variants.vulnerable],
        ["2. Güvenli — Kalkan Kapalı (enable_input_guard=false)", data.variants.secure_no_guard],
        ["3. Güvenli — Tam Savunma (enable_input_guard=true)", data.variants.secure_full],
      ].forEach(([label, v]) => {
        if (!v) return;
        const tr = document.createElement("tr");
        [label, formatStat(v.secret_leak), formatStat(v.attack_compliance)].forEach((val) => {
          const td = document.createElement("td");
          td.textContent = val;
          tr.appendChild(td);
        });
        sBody.appendChild(tr);
      });
      summaryTable.appendChild(sBody);
      benchModalBody.appendChild(summaryTable);
    }

    const table = document.createElement("table");
    table.className = "bench-table";

    const thead = document.createElement("thead");
    const headRow = document.createElement("tr");
    ["Kod", "Senaryo", "Zafiyetli (Sızıntı/Uyma)", "Kalkan Kapalı (Sızıntı/Uyma)", "Tam Savunma (Sızıntı/Uyma)"].forEach(
      (col) => {
        const th = document.createElement("th");
        th.textContent = col;
        headRow.appendChild(th);
      }
    );
    thead.appendChild(headRow);
    table.appendChild(thead);

    const tbody = document.createElement("tbody");
    (data.probes || []).forEach((p) => {
      const tr = document.createElement("tr");
      [
        p.probe_id,
        p.title,
        `%${p.vuln_leak_pct} / %${p.vuln_compliance_pct}`,
        `%${p.sec_noguard_leak_pct} / %${p.sec_noguard_compliance_pct}`,
        `%${p.sec_full_leak_pct} / %${p.sec_full_compliance_pct}`,
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

  renderShortcuts();
  setMode("vulnerable");
  refreshHealth();
  setInterval(refreshHealth, 30000);
})();

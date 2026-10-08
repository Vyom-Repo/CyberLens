/**
 * CyberLens Main Dashboard Application Controller
 */

import { ApiClient } from "./api.js";
import { ChartRenderer } from "./charts.js";
import { ClientValidator } from "./validator.js";
import { EffectsEngine } from "./effects.js";

let currentAnalysis = null;

document.addEventListener("DOMContentLoaded", () => {
  // Initialize cinematic lens calibration intro animation
  EffectsEngine.initIntroSequence();

  const iocInput = document.getElementById("iocInput");
  const analyzeBtn = document.getElementById("analyzeBtn");
  const detectedPill = document.getElementById("detectedPill");
  const alertBanner = document.getElementById("alertBanner");
  const dossierContainer = document.getElementById("dossierContainer");
  const loadingSkeleton = document.getElementById("loadingSkeleton");
  const exportBtn = document.getElementById("exportReportBtn");
  const copyJsonBtn = document.getElementById("copyJsonBtn");

  // Real-time input classification feedback
  iocInput.addEventListener("input", () => {
    const raw = iocInput.value;
    hideAlert();

    if (!raw.trim()) {
      detectedPill.textContent = "DETECTING...";
      detectedPill.className = "detected-pill";
      return;
    }

    const detected = ClientValidator.detectType(raw);
    if (detected) {
      detectedPill.textContent = detected;
      detectedPill.className = "detected-pill valid";
    } else {
      detectedPill.textContent = "SYNTAX CHECK";
      detectedPill.className = "detected-pill invalid";
    }
  });

  // Enter key trigger
  iocInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      triggerAnalysis();
    }
  });

  analyzeBtn.addEventListener("click", () => {
    triggerAnalysis();
  });

  // Quick sample pill clicks
  document.querySelectorAll(".sample-chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      const sample = chip.getAttribute("data-ioc");
      if (sample) {
        iocInput.value = sample;
        iocInput.dispatchEvent(new Event("input"));
        triggerAnalysis();
      }
    });
  });

  // Export JSON Report button
  if (exportBtn) {
    exportBtn.addEventListener("click", () => {
      if (!currentAnalysis || !currentAnalysis.id) return;
      window.location.href = ApiClient.getReportDownloadUrl(currentAnalysis.id);
    });
  }

  // Copy JSON Inspector button
  if (copyJsonBtn) {
    copyJsonBtn.addEventListener("click", () => {
      if (!currentAnalysis) return;
      navigator.clipboard.writeText(JSON.stringify(currentAnalysis.report, null, 2));
      const origText = copyJsonBtn.textContent;
      copyJsonBtn.textContent = "Copied to Clipboard!";
      setTimeout(() => {
        copyJsonBtn.textContent = origText;
      }, 2000);
    });
  }

  async function triggerAnalysis() {
    const raw = iocInput.value.trim();
    if (!raw) {
      showAlert("Please enter an indicator of compromise to evaluate.");
      return;
    }

    hideAlert();
    analyzeBtn.disabled = true;
    analyzeBtn.textContent = "Evaluating Threat...";
    dossierContainer.style.display = "none";
    loadingSkeleton.style.display = "block";

    try {
      const data = await ApiClient.analyze(raw);
      currentAnalysis = data;
      renderDossier(data);
    } catch (err) {
      showAlert(err.message || "Failed to analyze target indicator.");
    } finally {
      analyzeBtn.disabled = false;
      analyzeBtn.textContent = "Analyze Indicator";
      loadingSkeleton.style.display = "none";
    }
  }

  function showAlert(msg) {
    alertBanner.textContent = msg;
    alertBanner.className = "alert-banner visible error";
  }

  function hideAlert() {
    alertBanner.className = "alert-banner";
  }

  function renderDossier(analysis) {
    const report = analysis.report;
    const risk = report.risk_assessment;
    const sources = report.sources;
    const vt = sources.virustotal;
    const abuse = sources.abuseipdb;

    // 1. Executive Verdict Banner
    document.getElementById("dossierIoc").textContent = analysis.ioc;
    document.getElementById("dossierType").textContent = analysis.ioc_type;
    document.getElementById("dossierScore").textContent = risk.score;

    const level = risk.level.toLowerCase();
    const severityPill = document.getElementById("dossierSeverityPill");
    severityPill.textContent = `${risk.level} THREAT`;
    severityPill.className = `severity-pill ${level}`;

    document.getElementById("dossierConfidencePill").textContent = `${risk.confidence} CONFIDENCE`;
    document.getElementById("dossierSummary").textContent = analysis.summary;

    // Apply color accents to score card
    const bannerCard = document.getElementById("verdictCard");
    const colors = {
      low: { text: "var(--severity-low-text)", bg: "var(--severity-low-bg)", border: "var(--severity-low-border)", stripe: "var(--severity-low-accent)" },
      medium: { text: "var(--severity-med-text)", bg: "var(--severity-med-bg)", border: "var(--severity-med-border)", stripe: "var(--severity-med-accent)" },
      high: { text: "var(--severity-high-text)", bg: "var(--severity-high-bg)", border: "var(--severity-high-border)", stripe: "var(--severity-high-accent)" },
      critical: { text: "var(--severity-crit-text)", bg: "var(--severity-crit-bg)", border: "var(--severity-crit-border)", stripe: "var(--severity-crit-accent)" },
    };
    const c = colors[level] || colors.low;
    bannerCard.style.setProperty("--verdict-text", c.text);
    bannerCard.style.setProperty("--verdict-bg", c.bg);
    bannerCard.style.setProperty("--verdict-border", c.border);
    bannerCard.style.setProperty("--verdict-stripe", c.stripe);

    // 2. Chart.js Engine Doughnut
    if (vt && vt.engine_stats) {
      ChartRenderer.renderEngineDoughnut("engineChart", vt.engine_stats);
      document.getElementById("legMalicious").textContent = vt.engine_stats.malicious;
      document.getElementById("legSuspicious").textContent = vt.engine_stats.suspicious;
      document.getElementById("legHarmless").textContent = vt.engine_stats.harmless;
      document.getElementById("legUndetected").textContent = vt.engine_stats.undetected;
    }

    // 3. Justifications Rationale
    const justList = document.getElementById("justificationList");
    justList.innerHTML = "";
    risk.justifications.forEach((just, idx) => {
      const li = document.createElement("li");
      li.className = "justification-item";
      li.innerHTML = `
        <span class="justification-number">${idx + 1}</span>
        <span>${just}</span>
      `;
      justList.appendChild(li);
    });

    // 4. VirusTotal Telemetry Card
    if (vt && vt.status === "SUCCESS") {
      document.getElementById("vtCard").style.display = "flex";
      document.getElementById("vtRatio").textContent = `${(vt.detection_ratio * 100).toFixed(1)}%`;
      document.getElementById("vtEngines").textContent = `${vt.engine_stats.malicious} / ${vt.engine_stats.total}`;
      document.getElementById("vtReputation").textContent = vt.reputation_score;
      document.getElementById("vtLastSeen").textContent = vt.last_analysis_date
        ? new Date(vt.last_analysis_date).toLocaleDateString()
        : "Unrecorded";
    } else {
      document.getElementById("vtCard").style.display = "none";
    }

    // 5. AbuseIPDB Telemetry Card
    if (abuse && abuse.status === "SUCCESS") {
      document.getElementById("abuseCard").style.display = "flex";
      document.getElementById("abuseScore").textContent = `${abuse.abuse_confidence_score}%`;
      document.getElementById("abuseReports").textContent = abuse.total_reports;
      document.getElementById("abuseReporters").textContent = abuse.distinct_users;
      document.getElementById("abuseIsp").textContent = abuse.isp || "Unknown";
    } else {
      document.getElementById("abuseCard").style.display = "none";
    }

    // 6. JSON Viewer
    document.getElementById("rawJsonViewer").textContent = JSON.stringify(report, null, 2);

    dossierContainer.style.display = "flex";
    dossierContainer.scrollIntoView({ behavior: "smooth", block: "start" });
  }
});

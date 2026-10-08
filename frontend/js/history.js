/**
 * CyberLens Intelligence Registry / History Controller
 */

import { ApiClient } from "./api.js";
import { EffectsEngine } from "./effects.js";

document.addEventListener("DOMContentLoaded", () => {
  EffectsEngine.initCursor();

  const tableBody = document.getElementById("registryTableBody");
  const searchInput = document.getElementById("registrySearch");
  const riskFilter = document.getElementById("registryRiskFilter");
  const totalCountEl = document.getElementById("totalCount");
  const criticalCountEl = document.getElementById("criticalCount");
  const highCountEl = document.getElementById("highCount");
  const avgScoreEl = document.getElementById("avgScore");

  let searchTimeout = null;

  loadRegistryData();

  if (searchInput) {
    searchInput.addEventListener("input", () => {
      clearTimeout(searchTimeout);
      searchTimeout = setTimeout(() => {
        loadRegistryData();
      }, 300);
    });
  }

  if (riskFilter) {
    riskFilter.addEventListener("change", () => {
      loadRegistryData();
    });
  }

  async function loadRegistryData() {
    const search = searchInput ? searchInput.value.trim() : "";
    const riskLevel = riskFilter ? riskFilter.value.trim() : "";

    try {
      tableBody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align: center; padding: 32px; color: var(--text-muted);">
            Loading Registry Records...
          </td>
        </tr>
      `;

      const data = await ApiClient.getHistory(50, 0, search, riskLevel);
      renderTable(data.items);
      updateMetrics(data.items, data.total);
    } catch (err) {
      tableBody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align: center; padding: 32px; color: var(--severity-high-text);">
            ${err.message || "Failed to load registry records."}
          </td>
        </tr>
      `;
    }
  }

  function updateMetrics(items, total) {
    if (totalCountEl) totalCountEl.textContent = total;

    let crit = 0;
    let high = 0;
    let scoreSum = 0;

    items.forEach((item) => {
      if (item.risk_level === "CRITICAL") crit++;
      if (item.risk_level === "HIGH") high++;
      scoreSum += item.risk_score;
    });

    if (criticalCountEl) criticalCountEl.textContent = crit;
    if (highCountEl) highCountEl.textContent = high;
    if (avgScoreEl) {
      const avg = items.length > 0 ? Math.round(scoreSum / items.length) : 0;
      avgScoreEl.textContent = `${avg} / 100`;
    }
  }

  function renderTable(items) {
    if (!items || items.length === 0) {
      tableBody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align: center; padding: 40px; color: var(--text-muted);">
            No investigation records found in registry.
          </td>
        </tr>
      `;
      return;
    }

    tableBody.innerHTML = "";
    items.forEach((item) => {
      const tr = document.createElement("tr");
      const level = item.risk_level.toLowerCase();
      const dateFormatted = new Date(item.created_at).toLocaleString();

      tr.innerHTML = `
        <td style="font-family: var(--font-mono); font-weight: 700; color: var(--text-muted);">#${item.id}</td>
        <td class="table-ioc-cell">${item.ioc}</td>
        <td><span class="detected-pill" style="margin: 0;">${item.ioc_type}</span></td>
        <td>
          <span class="severity-pill ${level}">${item.risk_level} (${item.risk_score})</span>
        </td>
        <td style="font-size: 0.8125rem; color: var(--text-secondary);">${dateFormatted}</td>
        <td>
          <a href="${ApiClient.getReportDownloadUrl(item.id)}" class="btn-secondary" style="padding: 4px 10px; font-size: 0.75rem; text-decoration: none;">
            Download JSON
          </a>
        </td>
      `;
      tableBody.appendChild(tr);
    });
  }
});

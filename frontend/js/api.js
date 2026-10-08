/**
 * CyberLens API Client Wrapper
 */

const API_BASE = "";

export const ApiClient = {
  /**
   * Pre-validate and classify an IOC string
   */
  async validate(ioc) {
    const response = await fetch(`${API_BASE}/api/validate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ioc }),
    });
    return response.json();
  },

  /**
   * Execute comprehensive threat intelligence analysis
   */
  async analyze(ioc, iocType = null) {
    const response = await fetch(`${API_BASE}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ioc, ioc_type: iocType }),
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.detail || `Analysis failed (HTTP ${response.status})`);
    }

    return response.json();
  },

  /**
   * Fetch paginated investigation history
   */
  async getHistory(limit = 20, offset = 0, search = "", riskLevel = "") {
    const params = new URLSearchParams({
      limit: limit.toString(),
      offset: offset.toString(),
    });
    if (search) params.append("search", search);
    if (riskLevel) params.append("risk_level", riskLevel);

    const response = await fetch(`${API_BASE}/api/history?${params.toString()}`);
    if (!response.ok) {
      throw new Error("Failed to load investigation history.");
    }
    return response.json();
  },

  /**
   * Retrieve specific historical record by ID
   */
  async getRecordById(id) {
    const response = await fetch(`${API_BASE}/api/history/${id}`);
    if (!response.ok) {
      throw new Error(`Record #${id} not found.`);
    }
    return response.json();
  },

  /**
   * Download URL for JSON report
   */
  getReportDownloadUrl(id) {
    return `${API_BASE}/api/report/${id}`;
  },
};

/**
 * CyberLens Visual Engine Radar / Chart.js Integration
 */

let engineChartInstance = null;

export const ChartRenderer = {
  renderEngineDoughnut(canvasId, stats) {
    const canvas = document.getElementById(canvasId);
    if (!canvas || typeof Chart === "undefined") return;

    if (engineChartInstance) {
      engineChartInstance.destroy();
      engineChartInstance = null;
    }

    const { malicious = 0, suspicious = 0, harmless = 0, undetected = 0 } = stats || {};

    const ctx = canvas.getContext("2d");
    engineChartInstance = new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: ["Malicious", "Suspicious", "Harmless", "Undetected"],
        datasets: [
          {
            data: [malicious, suspicious, harmless, undetected],
            backgroundColor: [
              "#9E1026", // Deep Oxblood / Malicious
              "#D9822B", // Antiqued Amber / Suspicious
              "#1B8755", // British Racing Green / Harmless
              "#D9D2C3", // Muted Ivory Grey / Undetected
            ],
            borderColor: "#FFFFFF",
            borderWidth: 2,
            hoverOffset: 4,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "74%",
        plugins: {
          legend: {
            display: false,
          },
          tooltip: {
            backgroundColor: "#14171A",
            titleFont: { family: "-apple-system, sans-serif", size: 12, weight: "bold" },
            bodyFont: { family: "-apple-system, sans-serif", size: 12 },
            padding: 10,
            cornerRadius: 6,
          },
        },
      },
    });
  },
};

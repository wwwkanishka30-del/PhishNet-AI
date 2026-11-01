/**
 * PhishNet AI - Client-Side Interactive Logic
 * File: static/js/app.js
 */

document.addEventListener("DOMContentLoaded", () => {
  initSidebar();
  initScanForms();
  initSampleChips();
  initCharts();
  initCopyButtons();
});

/**
 * Mobile Sidebar Toggle Logic
 */
function initSidebar() {
  const toggleBtn = document.getElementById("sidebarToggle");
  const sidebar = document.querySelector(".sidebar");

  if (toggleBtn && sidebar) {
    toggleBtn.addEventListener("click", () => {
      sidebar.classList.toggle("open");
    });

    // Close sidebar when clicking outside on mobile
    document.addEventListener("click", (e) => {
      if (
        window.innerWidth <= 768 &&
        sidebar.classList.contains("open") &&
        !sidebar.contains(e.target) &&
        !toggleBtn.contains(e.target)
      ) {
        sidebar.classList.remove("open");
      }
    });
  }
}

/**
 * URL Scanner Form Handling & Loading State
 */
function initScanForms() {
  const forms = document.querySelectorAll(".scan-form");

  forms.forEach((form) => {
    const input = form.querySelector(".url-input-field");
    const clearBtn = form.querySelector(".btn-clear");
    const loader = form.querySelector(".loading-indicator");
    const submitBtn = form.querySelector("button[type='submit']");

    if (clearBtn && input) {
      clearBtn.addEventListener("click", () => {
        input.value = "";
        input.focus();
      });
    }

    form.addEventListener("submit", (e) => {
      const val = input ? input.value.trim() : "";
      if (!val) {
        e.preventDefault();
        alert("Please enter a URL to scan.");
        if (input) input.focus();
        return;
      }

      // Show spinner animation
      if (loader) {
        loader.style.display = "block";
      }
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.innerHTML = `
          <div class="spinner" style="width:16px;height:16px;border-width:2px;margin:0 6px 0 0;display:inline-block;vertical-align:middle;"></div>
          Analyzing...
        `;
      }
    });
  });
}

/**
 * Clickable Preset Chips for Fast Demonstration
 */
function initSampleChips() {
  const chips = document.querySelectorAll(".sample-chip");
  chips.forEach((chip) => {
    chip.addEventListener("click", () => {
      const sampleUrl = chip.getAttribute("data-url");
      const targetInput = document.querySelector(".url-input-field");
      if (targetInput && sampleUrl) {
        targetInput.value = sampleUrl;
        targetInput.focus();
      }
    });
  });
}

/**
 * Chart.js Visualizations on Dashboard
 */
function initCharts() {
  const donutEl = document.getElementById("riskDistributionChart");
  const trendEl = document.getElementById("recentScoresChart");

  if (!donutEl && !trendEl) return;

  // Fetch real statistics from /api/stats
  fetch("/api/stats")
    .then((res) => res.json())
    .then((stats) => {
      if (donutEl) {
        renderDonutChart(donutEl, stats);
      }
      if (trendEl) {
        renderTrendChart(trendEl, stats);
      }
    })
    .catch((err) => {
      console.warn("Could not load dynamic chart stats:", err);
    });
}

function renderDonutChart(canvas, stats) {
  const ctx = canvas.getContext("2d");
  const low = stats.low_risk_count || 0;
  const med = stats.medium_risk_count || 0;
  const high = stats.high_risk_count || 0;
  const total = stats.total_scans || 0;

  if (total === 0) {
    // Show empty state inside canvas container
    canvas.parentElement.innerHTML = `
      <div class="empty-state" style="padding: 2.5rem 1rem;">
        <p style="color: var(--text-dim); font-size: 0.9rem;">No URL scans recorded yet.<br>Scan your first link above to view risk distribution.</p>
      </div>
    `;
    return;
  }

  new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: ["Low Risk (0-29)", "Medium Risk (30-59)", "High Risk (60-100)"],
      datasets: [
        {
          data: [low, med, high],
          backgroundColor: ["#10b981", "#f59e0b", "#ef4444"],
          borderColor: "#111827",
          borderWidth: 3,
          hoverOffset: 6
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "bottom",
          labels: {
            color: "#94a3b8",
            font: { family: "Inter", size: 12 },
            padding: 16
          }
        },
        tooltip: {
          backgroundColor: "#1e293b",
          titleColor: "#f8fafc",
          bodyColor: "#94a3b8",
          borderColor: "rgba(255,255,255,0.1)",
          borderWidth: 1,
          padding: 10
        }
      },
      cutout: "68%"
    }
  });
}

function renderTrendChart(canvas, stats) {
  const ctx = canvas.getContext("2d");
  const recent = stats.recent_scores || [];

  if (recent.length === 0) {
    canvas.parentElement.innerHTML = `
      <div class="empty-state" style="padding: 2.5rem 1rem;">
        <p style="color: var(--text-dim); font-size: 0.9rem;">No timeline data available.<br>Submit URLs to populate scan trends.</p>
      </div>
    `;
    return;
  }

  const labels = recent.map((item, idx) => `Scan #${item.id}`);
  const scores = recent.map((item) => item.risk_score);
  const colors = scores.map((s) => (s >= 60 ? "#ef4444" : s >= 30 ? "#f59e0b" : "#10b981"));

  new Chart(ctx, {
    type: "bar",
    data: {
      labels: labels,
      datasets: [
        {
          label: "Risk Score",
          data: scores,
          backgroundColor: colors,
          borderRadius: 6
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: {
          min: 0,
          max: 100,
          grid: { color: "rgba(255, 255, 255, 0.05)" },
          ticks: { color: "#64748b", font: { family: "Inter", size: 11 } }
        },
        x: {
          grid: { display: false },
          ticks: { color: "#64748b", font: { family: "Inter", size: 11 } }
        }
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "#1e293b",
          borderColor: "rgba(255,255,255,0.1)",
          borderWidth: 1,
          callbacks: {
            label: (ctx) => `Risk Score: ${ctx.raw}/100`
          }
        }
      }
    }
  });
}

/**
 * Copy to Clipboard Helper
 */
function initCopyButtons() {
  const copyBtns = document.querySelectorAll(".btn-copy");
  copyBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      const text = btn.getAttribute("data-copy");
      if (text) {
        navigator.clipboard.writeText(text).then(() => {
          const original = btn.innerHTML;
          btn.innerHTML = `<span style="color:#10b981;">Copied!</span>`;
          setTimeout(() => {
            btn.innerHTML = original;
          }, 1800);
        });
      }
    });
  });
}

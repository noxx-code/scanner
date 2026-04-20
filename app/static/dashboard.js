/**
 * dashboard.js — powers the scan dashboard.
 *
 * Responsibilities:
 *  - Guard: redirect to /login if no JWT is present.
 *  - Load and display existing scan reports.
 *  - Submit new scan requests.
 *  - Auto-refresh running scans every 5 seconds.
 *  - Show vulnerability details in a modal.
 */

const API = "";
const TOKEN_KEY = "token";

// ---------------------------------------------------------------------------
// Auth guard
// ---------------------------------------------------------------------------
const token = localStorage.getItem(TOKEN_KEY);
if (!token) {
  window.location.href = "/login";
}

const authHeaders = {
  "Content-Type": "application/json",
  Authorization: `Bearer ${token}`,
};

// ---------------------------------------------------------------------------
// Populate navbar username
// ---------------------------------------------------------------------------
(async () => {
  try {
    const res = await fetch(`${API}/auth/me`, { headers: authHeaders });
    if (!res.ok) {
      // Token expired or invalid — force re-login
      localStorage.removeItem(TOKEN_KEY);
      window.location.href = "/login";
      return;
    }
    const user = await res.json();
    document.getElementById("nav-username").textContent = `👤 ${user.username}`;
  } catch {
    // ignore
  }
})();

// ---------------------------------------------------------------------------
// Logout
// ---------------------------------------------------------------------------
document.getElementById("logout-btn").addEventListener("click", async () => {
  await fetch(`${API}/auth/logout`, { method: "POST", headers: authHeaders }).catch(() => {});
  localStorage.removeItem(TOKEN_KEY);
  window.location.href = "/login";
});

// ---------------------------------------------------------------------------
// Load reports
// ---------------------------------------------------------------------------
const POLL_INTERVAL_MS = 7000;
let pollingIntervalId = null;
let isLoadingReports = false;

function stopPolling() {
  if (pollingIntervalId !== null) {
    clearInterval(pollingIntervalId);
    pollingIntervalId = null;
  }
}

function startPolling() {
  // Always reset first so there is only one active interval.
  stopPolling();
  pollingIntervalId = setInterval(() => {
    if (document.hidden) return;
    loadReports();
  }, POLL_INTERVAL_MS);
}

async function loadReports() {
  if (isLoadingReports) return;
  isLoadingReports = true;

  const loading       = document.getElementById("loading");
  const noScans       = document.getElementById("no-scans");
  const tableWrapper  = document.getElementById("scans-table-wrapper");
  const tbody         = document.getElementById("scans-tbody");

  loading.classList.remove("hidden");
  noScans.classList.add("hidden");
  tableWrapper.classList.add("hidden");

  try {
    const res = await fetch(`${API}/reports`, { headers: authHeaders });
    if (!res.ok) throw new Error("Failed to load reports");
    const scans = await res.json();

    loading.classList.add("hidden");

    if (scans.length === 0) {
      stopPolling();
      noScans.classList.remove("hidden");
      return;
    }

    tbody.innerHTML = scans.map(renderScanRow).join("");
    tableWrapper.classList.remove("hidden");

    // Smart polling: only poll while work is still in progress.
    const hasRunning = scans.some((s) => s.status === "running" || s.status === "pending");
    if (hasRunning && !document.hidden) {
      startPolling();
    } else {
      stopPolling();
    }
  } catch {
    loading.classList.add("hidden");
  } finally {
    isLoadingReports = false;
  }
}

function renderScanRow(scan) {
  const created = new Date(scan.created_at).toLocaleString();
  const vulnCount = scan.vulnerabilities ? scan.vulnerabilities.length : 0;
  const badge = `<span class="badge badge-${scan.status}">${scan.status}</span>`;
    const detailBtn = `<button type="button" class="btn btn-sm btn-outline view-vulns-btn"
      data-scan-id="${scan.id}"
      data-target-url="${escHtml(scan.target_url)}">Details</button>`;
    const exportJsonBtn = `<button type="button" class="btn btn-sm btn-outline export-json-btn"
      data-scan-id="${scan.id}">JSON</button>`;
    const exportHtmlBtn = `<button type="button" class="btn btn-sm btn-outline export-html-btn"
      data-scan-id="${scan.id}">HTML</button>`;
    const deleteBtn = `<button type="button" class="btn btn-sm btn-danger delete-scan-btn"
      data-scan-id="${scan.id}">Delete</button>`;
  return `<tr>
    <td>${scan.id}</td>
    <td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
        title="${escHtml(scan.target_url)}">${escHtml(scan.target_url)}</td>
    <td>${scan.depth}</td>
    <td>${badge}</td>
    <td>${created}</td>
    <td>${vulnCount > 0 ? `<span style="color:var(--danger);font-weight:700;">${vulnCount}</span>` : "0"}</td>
    <td style="display:flex;gap:8px;flex-wrap:wrap;">${detailBtn}${exportJsonBtn}${exportHtmlBtn}${deleteBtn}</td>
  </tr>`;
}

async function deleteScan(scanId) {
  const ok = window.confirm(`Delete report #${scanId}? This cannot be undone.`);
  if (!ok) return;

  try {
    const res = await fetch(`${API}/reports/${scanId}`, {
      method: "DELETE",
      headers: authHeaders,
    });

    if (!res.ok) {
      let message = "Failed to delete report.";
      try {
        const data = await res.json();
        if (res.status === 403) {
          message = "You do not have permission to delete this report.";
        } else if (res.status === 404) {
          message = "This report no longer exists.";
        } else {
          message = data.detail || message;
        }
      } catch {
        // keep fallback message
      }
      showDashboardError(message);
      return;
    }

    const row = document.querySelector(`.delete-scan-btn[data-scan-id="${scanId}"]`)?.closest("tr");
    if (row) row.remove();

    const tbody = document.getElementById("scans-tbody");
    if (!tbody.querySelector("tr")) {
      document.getElementById("scans-table-wrapper").classList.add("hidden");
      document.getElementById("no-scans").classList.remove("hidden");
    }

    showDashboardSuccess(`Report #${scanId} deleted.`);
  } catch {
    showDashboardError("Network error while deleting report. Please try again.");
  }
}

function setupTableActions() {
  const tbody = document.getElementById("scans-tbody");
  if (!tbody || tbody.dataset.actionsBound === "1") return;

  tbody.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;

    const detailBtn = target.closest(".view-vulns-btn");
    if (detailBtn instanceof HTMLElement) {
      openVulnModal(detailBtn.dataset.scanId, detailBtn.dataset.targetUrl);
      return;
    }

    const deleteBtn = target.closest(".delete-scan-btn");
    if (deleteBtn instanceof HTMLElement) {
      deleteScan(deleteBtn.dataset.scanId);
      return;
    }

    const exportJsonBtn = target.closest(".export-json-btn");
    if (exportJsonBtn instanceof HTMLElement) {
      const scanId = exportJsonBtn.dataset.scanId;
      window.open(`${API}/reports/${scanId}/json`, "_blank", "noopener");
      return;
    }

    const exportHtmlBtn = target.closest(".export-html-btn");
    if (exportHtmlBtn instanceof HTMLElement) {
      const scanId = exportHtmlBtn.dataset.scanId;
      window.open(`${API}/reports/${scanId}/html`, "_blank", "noopener");
    }
  });

  tbody.dataset.actionsBound = "1";
}

function showDashboardError(message) {
  const errEl = document.getElementById("scan-error");
  const okEl = document.getElementById("scan-success");
  okEl.classList.add("hidden");
  errEl.textContent = message;
  errEl.classList.remove("hidden");
}

function showDashboardSuccess(message) {
  const errEl = document.getElementById("scan-error");
  const okEl = document.getElementById("scan-success");
  errEl.classList.add("hidden");
  okEl.textContent = message;
  okEl.classList.remove("hidden");
}

// ---------------------------------------------------------------------------
// Start scan
// ---------------------------------------------------------------------------
document.getElementById("scan-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const errEl = document.getElementById("scan-error");
  const okEl  = document.getElementById("scan-success");
  errEl.classList.add("hidden");
  okEl.classList.add("hidden");

  const body = {
    target_url: document.getElementById("target-url").value.trim(),
    depth: parseInt(document.getElementById("depth").value, 10),
    respect_robots_txt: document.getElementById("respect-robots").value === "true",
  };

  try {
    const res = await fetch(`${API}/scan`, {
      method: "POST",
      headers: authHeaders,
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) {
      errEl.textContent = data.detail || "Failed to start scan.";
      errEl.classList.remove("hidden");
      return;
    }
    okEl.textContent = `Scan #${data.id} started for ${body.target_url}`;
    okEl.classList.remove("hidden");
    document.getElementById("target-url").value = "";
    loadReports();
  } catch {
    errEl.textContent = "Network error.";
    errEl.classList.remove("hidden");
  }
});

// ---------------------------------------------------------------------------
// Refresh button
// ---------------------------------------------------------------------------
document.getElementById("refresh-btn").addEventListener("click", loadReports);

// Pause polling when tab is hidden; re-check scan state when visible again.
document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    stopPolling();
    return;
  }
  loadReports();
});

// Ensure polling is cleaned up when leaving the page.
window.addEventListener("pagehide", stopPolling);
window.addEventListener("beforeunload", stopPolling);

// ---------------------------------------------------------------------------
// Vulnerability modal
// ---------------------------------------------------------------------------
async function openVulnModal(scanId, targetUrl) {
  const modal   = document.getElementById("vuln-modal");
  const title   = document.getElementById("modal-title");
  const body    = document.getElementById("modal-body");

  title.textContent = `Vulnerabilities — ${targetUrl}`;
  body.innerHTML = "<p>Loading…</p>";
  modal.classList.remove("hidden");

  try {
    const res = await fetch(`${API}/reports/${scanId}`, { headers: authHeaders });
    const scan = await res.json();
    const vulns = scan.vulnerabilities || [];

    if (vulns.length === 0) {
      body.innerHTML = '<p class="no-vulns">✅ No vulnerabilities found.</p>';
    } else {
      body.innerHTML = `
        <table class="vuln-table">
          <thead>
            <tr>
              <th>URL</th>
              <th>Parameter</th>
              <th>Type</th>
              <th>Severity</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>
            ${vulns.map((v) => `<tr>
              <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;" title="${escHtml(v.url)}">${escHtml(v.url)}</td>
              <td><code>${escHtml(v.parameter)}</code></td>
              <td><strong>${escHtml(v.vuln_type)}</strong></td>
              <td><span class="sev-${v.severity}">${v.severity.toUpperCase()}</span></td>
              <td>${escHtml(v.detail || "")}</td>
            </tr>`).join("")}
          </tbody>
        </table>`;
    }
  } catch {
    body.innerHTML = '<p style="color:var(--danger)">Failed to load details.</p>';
  }
}

document.getElementById("modal-close").addEventListener("click", () => {
  document.getElementById("vuln-modal").classList.add("hidden");
});
document.getElementById("modal-backdrop").addEventListener("click", () => {
  document.getElementById("vuln-modal").classList.add("hidden");
});

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------
function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ---------------------------------------------------------------------------
// Initial load
// ---------------------------------------------------------------------------
setupTableActions();
loadReports();

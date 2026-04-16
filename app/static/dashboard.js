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
let autoRefreshTimer = null;

async function loadReports() {
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
      noScans.classList.remove("hidden");
      return;
    }

    tbody.innerHTML = scans.map(renderScanRow).join("");
    tableWrapper.classList.remove("hidden");

    // Re-attach detail button listeners
    document.querySelectorAll(".view-vulns-btn").forEach((btn) => {
      btn.addEventListener("click", () => openVulnModal(btn.dataset.scanId, btn.dataset.targetUrl));
    });

    // Auto-refresh if any scan is still running
    const hasRunning = scans.some((s) => s.status === "running" || s.status === "pending");
    if (hasRunning) {
      clearTimeout(autoRefreshTimer);
      autoRefreshTimer = setTimeout(loadReports, 5000);
    }
  } catch {
    loading.classList.add("hidden");
  }
}

function renderScanRow(scan) {
  const created = new Date(scan.created_at).toLocaleString();
  const vulnCount = scan.vulnerabilities ? scan.vulnerabilities.length : 0;
  const badge = `<span class="badge badge-${scan.status}">${scan.status}</span>`;
  const detailBtn = `<button class="btn btn-sm btn-outline view-vulns-btn"
      data-scan-id="${scan.id}"
      data-target-url="${escHtml(scan.target_url)}">Details</button>`;
  return `<tr>
    <td>${scan.id}</td>
    <td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
        title="${escHtml(scan.target_url)}">${escHtml(scan.target_url)}</td>
    <td>${scan.depth}</td>
    <td>${badge}</td>
    <td>${created}</td>
    <td>${vulnCount > 0 ? `<span style="color:var(--danger);font-weight:700;">${vulnCount}</span>` : "0"}</td>
    <td>${detailBtn}</td>
  </tr>`;
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
loadReports();

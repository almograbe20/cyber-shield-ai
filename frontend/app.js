// Cyber Shield AI — frontend logic (Phase 3: hybrid AI + trend + PDF)
const $ = (id) => document.getElementById(id);

const SAMPLE = `import os
import hashlib

API_KEY = "sk_live_9f8a7b6c5d4e3f2a1b0c"   # exposed secret

def login(username, password):
    # SQL injection
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    db.execute(query)

def run_ping(host):
    # OS command injection
    os.system("ping -c 1 " + host)

def hash_pw(pw):
    # weak hashing
    return hashlib.md5(pw.encode()).hexdigest()

def render(name):
    # XSS
    document.innerHTML = "Hello " + name

DEBUG = True`;

const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };

// ---------- token management ----------
const TOKEN_KEY = "cybershield_token";
let token = localStorage.getItem(TOKEN_KEY) || null;
let currentUser = null;

function authHeaders() {
  return token ? { Authorization: "Bearer " + token } : {};
}

// require sign-in before using the scanner
function requireLogin() {
  if (!token) {
    openAuth("login");
    return false;
  }
  return true;
}

// ---------- server health + AI mode ----------
async function checkHealth() {
  const chip = $("healthChip");
  try {
    const d = await (await fetch("/api/health")).json();
    chip.textContent = "● online · " + d.version;
    chip.className = "status-chip ok";
  } catch {
    chip.textContent = "● offline";
    chip.className = "status-chip err";
  }
}

async function loadAiStatus() {
  const chip = $("aiChip");
  try {
    const d = await (await fetch("/api/ai-status")).json();
    if (d.mode === "claude") {
      chip.textContent = "🤖 Claude API";
      chip.className = "ai-chip claude";
      chip.title = "AI analysis via Claude API";
    } else {
      chip.textContent = "🤖 AI";
      chip.className = "ai-chip";
      chip.title = "Built-in AI analysis. Set ANTHROPIC_API_KEY to use Claude API.";
    }
  } catch { chip.textContent = "🤖 —"; }
}

// ---------- user session ----------
async function loadMe() {
  if (!token) { renderAuthArea(null); return; }
  try {
    const d = await (await fetch("/api/me", { headers: authHeaders() })).json();
    currentUser = d.user;
    renderAuthArea(currentUser);
    if (currentUser) loadHistory();
  } catch { renderAuthArea(null); }
}

function renderAuthArea(user) {
  const area = $("authArea");
  let items = "";
  if (user) {
    const badge = user.is_admin ? '<span class="admin-badge">ADMIN</span>' : "";
    items += `<div class="dd-label">👤 ${esc(user.username)} ${badge}</div>`;
    if (user.is_admin) {
      items += `<button class="dd-item" data-act="blocked">🚫 Blocked users <span class="dd-count" id="blockedCountBadge" hidden></span></button>`;
    }
    items += `<button class="dd-item" data-act="logout">🚪 Sign out</button>`;
  } else {
    items += `<button class="dd-item" data-act="login">🔑 Login</button>`;
    items += `<button class="dd-item" data-act="register">✨ Sign up</button>`;
  }
  area.innerHTML = `
    <div class="settings-menu">
      <button class="ghost settings-btn" id="settingsBtn">⚙ Settings ▾</button>
      <div class="settings-dropdown" id="settingsDropdown" hidden>${items}</div>
    </div>`;

  $("settingsBtn").onclick = (e) => {
    e.stopPropagation();
    const dd = $("settingsDropdown");
    dd.hidden = !dd.hidden;
  };
  area.querySelectorAll(".dd-item").forEach((btn) => {
    btn.onclick = () => {
      $("settingsDropdown").hidden = true;
      const act = btn.dataset.act;
      if (act === "login") openAuth("login");
      else if (act === "register") openAuth("register");
      else if (act === "logout") logout();
      else if (act === "blocked") showBlockedUsers();
    };
  });

  // panels + sign-in hint
  if (user) {
    $("historyPanel").hidden = false;
    $("saveNote").textContent = "";
    if (user.is_admin) { loadAdmin(); startAdminAutoRefresh(); }
    else { $("adminPanel").hidden = true; stopAdminAutoRefresh(); }
  } else {
    $("historyPanel").hidden = true;
    $("trendPanel").hidden = true;
    $("adminPanel").hidden = true;
    $("saveNote").textContent = "🔒 Sign in to use the scanner.";
    stopAdminAutoRefresh();
  }
}

// auto-refresh the admin panel so new users / scans appear live
let adminTimer = null;
function startAdminAutoRefresh() {
  if (adminTimer) return;
  adminTimer = setInterval(() => { if (!$("adminPanel").hidden) loadAdmin(); }, 15000);
}
function stopAdminAutoRefresh() {
  if (adminTimer) { clearInterval(adminTimer); adminTimer = null; }
}

// close the dropdown when clicking anywhere else
document.addEventListener("click", (e) => {
  const dd = $("settingsDropdown");
  if (dd && !dd.hidden && !e.target.closest(".settings-menu")) dd.hidden = true;
});

// ---------- blocked users modal ----------
async function showBlockedUsers() {
  try {
    const d = await (await fetch("/api/admin/overview", { headers: authHeaders() })).json();
    const blocked = (d.users || []).filter((u) => u.is_blocked);
    const list = $("blockedList");
    list.innerHTML = blocked.length
      ? blocked.map((u) => `
        <div class="blocked-row">
          <span class="bu">${esc(u.username)}</span>
          <button class="block-btn unblock" onclick="unblockFromModal(${u.id})">Unblock</button>
        </div>`).join("")
      : '<p class="dim" style="padding:8px">No blocked users.</p>';
    $("blockedModal").hidden = false;
  } catch { alert("Could not load blocked users."); }
}
window.showBlockedUsers = showBlockedUsers;

async function unblockFromModal(userId) {
  await toggleBlock(userId, false, true);
  showBlockedUsers();  // refresh the modal
}
window.unblockFromModal = unblockFromModal;

// ---------- admin panel ----------
async function loadAdmin() {
  try {
    const d = await (await fetch("/api/admin/overview", { headers: authHeaders() })).json();
    if (!d.users) return;
    $("adminPanel").hidden = false;
    const totalScans = d.users.reduce((n, u) => n + u.scan_count, 0);
    const blockedCount = d.users.filter((u) => u.is_blocked).length;
    $("adminSummary").textContent = `${d.total_users} users · ${totalScans} scans total · ${blockedCount} blocked`;
    const badge = $("blockedCountBadge");
    if (badge) { badge.textContent = blockedCount; badge.hidden = blockedCount === 0; }
    $("adminList").innerHTML = d.users.map((u) => {
      const canBlock = !u.is_admin && u.id !== (currentUser && currentUser.id);
      return `
      <div class="admin-user ${u.is_blocked ? "blocked" : ""}">
        <div class="admin-user-top" onclick="this.parentElement.classList.toggle('open')">
          <span class="uname ${u.is_admin ? "admin" : ""}">${esc(u.username)}</span>
          ${u.is_admin ? '<span class="admin-badge">ADMIN</span>' : ""}
          ${u.is_blocked ? '<span class="blocked-badge">BLOCKED</span>' : ""}
          <span class="umeta">${u.scan_count} scan(s) · joined ${fmtDate(u.created_at)}</span>
          ${canBlock ? `<button class="block-btn ${u.is_blocked ? "unblock" : ""}"
             title="${u.is_blocked ? "Unblock user" : "Block user"}"
             onclick="event.stopPropagation(); toggleBlock(${u.id}, ${!u.is_blocked})">
             ${u.is_blocked ? "↺" : "✕"}</button>` : ""}
        </div>
        <div class="admin-user-scans">
          ${u.scans.length ? u.scans.map((s) => `
            <div class="admin-scan">
              <span class="sc" style="color:${scoreColor(s.security_score)}">${s.security_score}</span>
              <span class="st">${esc(s.target || "untitled")} <span class="sd">· ${esc(s.language)} · ${s.total_findings} issue(s)</span></span>
              <span class="sd">${fmtDate(s.created_at)}</span>
            </div>`).join("") : '<div class="admin-scan none">No scans yet.</div>'}
        </div>
      </div>`;
    }).join("");
  } catch {}
}

async function toggleBlock(userId, blocked, skipConfirm) {
  if (blocked && !skipConfirm && !confirm("Block this user? They will be signed out and unable to log in.")) return;
  try {
    const r = await fetch("/api/admin/block", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify({ user_id: userId, blocked }),
    });
    const d = await r.json();
    if (!r.ok) { alert(d.detail || "Error"); return; }
    loadAdmin();
  } catch { alert("Could not update the user."); }
}
window.toggleBlock = toggleBlock;

// ---------- auth modal ----------
let authMode = "login";
function openAuth(mode) {
  $("authModal").hidden = false;
  $("authError").textContent = "";
  setMode(mode === "register" ? "register" : "login");
}
function closeAuth() { $("authModal").hidden = true; }

function setMode(mode) {
  authMode = mode;
  $("tabLogin").classList.toggle("active", mode === "login");
  $("tabRegister").classList.toggle("active", mode === "register");
  $("authSubmit").textContent = mode === "login" ? "Sign in" : "Create account";
  $("authError").textContent = "";
}

async function submitAuth() {
  const username = $("authUser").value.trim();
  const password = $("authPass").value;
  const err = $("authError");
  if (!username || !password) { err.textContent = "Fill in both fields"; return; }
  try {
    const r = await fetch("/api/" + (authMode === "login" ? "login" : "register"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const d = await r.json();
    if (!r.ok) { err.textContent = d.detail || "Error"; return; }
    token = d.token;
    localStorage.setItem(TOKEN_KEY, token);
    closeAuth();
    $("authUser").value = ""; $("authPass").value = "";
    await loadMe();
  } catch (e) { err.textContent = "Could not reach the server"; }
}

async function logout() {
  try { await fetch("/api/logout", { method: "POST", headers: authHeaders() }); } catch {}
  token = null; currentUser = null;
  localStorage.removeItem(TOKEN_KEY);
  renderAuthArea(null);
}

// ---------- scanning ----------
$("sampleBtn").onclick = () => { $("codeInput").value = SAMPLE; $("filename").value = "app.py"; };

// upload a code file from the device -> read it into the editor
$("uploadBtn").onclick = () => { if (!requireLogin()) return; $("fileInput").click(); };
$("fileInput").onchange = (e) => {
  const file = e.target.files[0];
  if (!file) return;
  if (file.size > 1024 * 1024) { alert("File too large (max 1 MB)."); e.target.value = ""; return; }
  const reader = new FileReader();
  reader.onload = () => {
    $("codeInput").value = reader.result;
    $("filename").value = file.name;
  };
  reader.onerror = () => alert("Could not read the file.");
  reader.readAsText(file);
  e.target.value = "";  // allow re-uploading the same file
};

$("scanBtn").onclick = async () => {
  if (!requireLogin()) return;
  const code = $("codeInput").value.trim();
  if (!code) { alert("Paste some code first"); return; }
  const btn = $("scanBtn");
  btn.disabled = true;
  btn.querySelector(".btn-label").innerHTML = '<span class="spinner"></span> Scanning...';
  try {
    const r = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify({ code, filename: $("filename").value.trim() }),
    });
    const data = await r.json();
    if (data.error) { alert(data.error); return; }
    renderResult(data);
    $("saveNote").textContent = data.saved
      ? "✅ Scan saved to your history"
      : "ℹ️ Sign in to save your scans to history";
    if (data.saved) loadHistory();
  } catch (e) {
    alert("Server connection error: " + e.message);
  } finally {
    btn.disabled = false;
    btn.querySelector(".btn-label").textContent = "🔍 Run scan";
  }
};

function renderResult(data) {
  $("emptyState").hidden = true;
  $("resultsPanel").hidden = false;
  const s = data.summary;
  $("summaryGrid").innerHTML = `
    <div class="stat score"><div class="num">${data.security_score}</div><div class="label">Security score /100</div></div>
    <div class="stat critical"><div class="num">${s.critical || 0}</div><div class="label">Critical</div></div>
    <div class="stat high"><div class="num">${s.high || 0}</div><div class="label">High</div></div>
    <div class="stat medium"><div class="num">${s.medium || 0}</div><div class="label">Medium</div></div>
    <div class="stat low"><div class="num">${s.low || 0}</div><div class="label">Low</div></div>`;
  $("aiSummary").textContent = data.ai_summary || "";
  $("modeTag").textContent = data.ai_mode === "claude" ? "Claude API analysis" : "AI analysis";

  const evidenceLabel = data.language === "website" ? "Evidence" : "Detected code";
  const list = $("findingsList");
  if (!data.findings.length) {
    list.innerHTML = '<div class="empty" style="padding:30px"><div class="empty-icon">✅</div><p>No vulnerabilities detected with the current rules.</p></div>';
  } else {
    list.innerHTML = data.findings.map((f) => `
      <div class="finding ${f.severity}">
        <div class="finding-top" onclick="this.parentElement.classList.toggle('open')">
          <span class="sev-badge ${f.severity}">${SEV_LABEL[f.severity] || f.severity}</span>
          <span class="finding-title">${esc(f.title)}</span>
          <span class="finding-meta">${f.cwe}${f.line ? " · line " + f.line : ""}</span>
          <span class="chev">▾</span>
        </div>
        <div class="finding-body">
          <div class="row"><span class="k">${evidenceLabel}</span><div class="snippet">${esc(f.snippet)}</div></div>
          <div class="row"><span class="k">🤖 AI explanation</span><div>${esc(f.ai_explanation || f.description)}</div></div>
          <div class="row"><span class="k">✅ How to fix</span><div class="fix">${esc(f.remediation)}</div></div>
          <div class="row"><span class="finding-meta">Confidence: ${esc(f.ai_confidence || "—")}</span></div>
        </div>
      </div>`).join("");
  }
  $("resultsPanel").scrollIntoView({ behavior: "smooth" });
}

// ---------- PDF export (via print) ----------
$("exportBtn").onclick = () => {
  document.querySelectorAll(".finding").forEach((f) => f.classList.add("open"));
  window.print();
};

// ---------- scan history ----------
async function loadHistory() {
  if (!token) return;
  try {
    const d = await (await fetch("/api/history", { headers: authHeaders() })).json();
    const scans = d.scans || [];
    renderTrend(scans);
    const list = $("historyList");
    if (!scans.length) {
      list.innerHTML = '<p class="dim" style="padding:10px">No saved scans yet.</p>';
      return;
    }
    list.innerHTML = scans.map((r) => `
      <div class="history-item" onclick="viewScan(${r.id})">
        <div class="history-score" style="color:${scoreColor(r.security_score)}">${r.security_score}</div>
        <div class="history-main">
          <div class="hf">${esc(r.filename || "untitled")} · <span class="dim">${esc(r.language)}</span></div>
          <div class="hd">${fmtDate(r.created_at)} · ${r.total_findings} issue(s)</div>
        </div>
        <div class="history-badges">
          ${r.critical ? `<span class="mini-badge critical">${r.critical} critical</span>` : ""}
          ${r.high ? `<span class="mini-badge high">${r.high} high</span>` : ""}
          ${r.medium ? `<span class="mini-badge medium">${r.medium} medium</span>` : ""}
          ${r.low ? `<span class="mini-badge low">${r.low} low</span>` : ""}
        </div>
      </div>`).join("");
  } catch {}
}

async function viewScan(id) {
  try {
    const data = await (await fetch("/api/scan/" + id, { headers: authHeaders() })).json();
    renderResult(data);
  } catch { alert("Could not load the scan"); }
}
window.viewScan = viewScan;

// ---------- security score trend chart (inline SVG) ----------
function renderTrend(scans) {
  const panel = $("trendPanel");
  const chart = $("trendChart");
  if (!scans || scans.length < 2) { panel.hidden = true; return; }
  panel.hidden = false;

  // oldest -> newest
  const pts = scans.slice().reverse().map((s) => s.security_score);
  const W = 720, H = 240, pad = 36;
  const n = pts.length;
  const stepX = (W - pad * 2) / (n - 1);
  const x = (i) => pad + i * stepX;
  const y = (v) => H - pad - (v / 100) * (H - pad * 2);

  const line = pts.map((v, i) => `${i === 0 ? "M" : "L"} ${x(i).toFixed(1)} ${y(v).toFixed(1)}`).join(" ");
  const area = `${line} L ${x(n - 1).toFixed(1)} ${H - pad} L ${x(0).toFixed(1)} ${H - pad} Z`;

  const gridY = [0, 25, 50, 75, 100].map((v) => `
    <line x1="${pad}" y1="${y(v)}" x2="${W - pad}" y2="${y(v)}" stroke="rgba(255,255,255,.08)" />
    <text x="${pad - 8}" y="${y(v) + 4}" fill="#8a94b8" font-size="11" text-anchor="end">${v}</text>`).join("");

  const dots = pts.map((v, i) => `
    <circle cx="${x(i)}" cy="${y(v)}" r="4.5" fill="${scoreColor(v)}" stroke="#0a0e1a" stroke-width="2">
      <title>Score ${v}</title>
    </circle>`).join("");

  chart.innerHTML = `
    <svg viewBox="0 0 ${W} ${H}" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="rgba(56,232,255,.35)" />
          <stop offset="100%" stop-color="rgba(56,232,255,0)" />
        </linearGradient>
      </defs>
      ${gridY}
      <path d="${area}" fill="url(#trendFill)" />
      <path d="${line}" fill="none" stroke="#38e8ff" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round" />
      ${dots}
    </svg>`;
}

// ---------- helpers ----------
function scoreColor(s) {
  if (s >= 80) return "var(--ok)";
  if (s >= 50) return "var(--medium)";
  return "var(--critical)";
}
function fmtDate(iso) {
  try {
    const d = new Date(iso);
    return d.toLocaleString("en-US", { dateStyle: "medium", timeStyle: "short" });
  } catch { return iso; }
}
function esc(str) {
  return String(str).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

// ---------- scan type tabs (Code / Website) ----------
function showScanTab(which) {
  const code = which === "code";
  $("tabCode").classList.toggle("active", code);
  $("tabWeb").classList.toggle("active", !code);
  $("codeView").hidden = !code;
  $("webView").hidden = code;
}
$("tabCode").onclick = () => showScanTab("code");
$("tabWeb").onclick = () => showScanTab("web");

// ---------- website scan ----------
$("webScanBtn").onclick = async () => {
  if (!requireLogin()) return;
  const url = $("urlInput").value.trim();
  if (!url) { alert("Enter a website URL first"); return; }
  const active = $("activeToggle").checked;
  const btn = $("webScanBtn");
  btn.disabled = true;
  btn.querySelector(".btn-label").innerHTML = '<span class="spinner"></span> Scanning website...';
  $("verifyBox").hidden = true;
  try {
    const r = await fetch("/api/web-scan", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify({ url, active }),
    });
    const data = await r.json();
    if (!r.ok) { alert(data.detail || "Error"); return; }
    if (data.needs_verification) { showVerifyBox(data.token); return; }
    renderResult(data);
    $("saveNote").textContent = data.saved
      ? `✅ Website scan saved (${data.scan_type})`
      : "ℹ️ Sign in to save your scans to history";
    if (data.saved) loadHistory();
  } catch (e) {
    alert("Server connection error: " + e.message);
  } finally {
    btn.disabled = false;
    btn.querySelector(".btn-label").textContent = "🌐 Scan website";
  }
};

function showVerifyBox(token) {
  const box = $("verifyBox");
  box.hidden = false;
  box.innerHTML = `
    <h4>⚠ Ownership verification required for an active scan</h4>
    <p>Prove you own this site using one of the options below, then scan again:</p>
    <div class="opt">Option 1 — host this file at <b>/.well-known/cybershield-verify.txt</b> containing:</div>
    <code>${esc(token)}</code>
    <div class="opt">Option 2 — add this meta tag to your homepage &lt;head&gt;:</div>
    <code>&lt;meta name="cybershield-verify" content="${esc(token)}"&gt;</code>
    <div class="opt">(localhost / 127.0.0.1 is trusted automatically for testing.)</div>`;
}

// ---------- wire up ----------
$("tabLogin").onclick = () => setMode("login");
$("tabRegister").onclick = () => setMode("register");
$("authSubmit").onclick = submitAuth;
$("authClose").onclick = closeAuth;
$("authModal").onclick = (e) => { if (e.target === $("authModal")) closeAuth(); };
$("authPass").addEventListener("keydown", (e) => { if (e.key === "Enter") submitAuth(); });
$("blockedClose").onclick = () => { $("blockedModal").hidden = true; };
$("blockedModal").onclick = (e) => { if (e.target === $("blockedModal")) $("blockedModal").hidden = true; };
$("adminRefresh").onclick = loadAdmin;

checkHealth();
loadAiStatus();
loadMe();

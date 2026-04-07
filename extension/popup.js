/**
 * ThreatShield AI — Extension Popup Script
 * Separated from popup.html to comply with MV3 Content Security Policy.
 * Inline scripts are blocked in MV3 — all JS must be in external files.
 */
let isActive = true;

async function init() {
  // get shield status
  try {
    const status = await chrome.runtime.sendMessage({ type: "getStatus" });
    isActive = status.shieldActive;
    document.getElementById("blocked-count").textContent = status.blockedCount;
    updateUI();
  } catch (e) {
    console.error("Status error:", e);
  }

  // check daemon
  try {
    const r = await fetch("http://localhost:8766/status", {
      signal: AbortSignal.timeout(2000)
    });
    if (r.ok) {
      const d = await r.json();
      const el = document.getElementById("daemon-status");
      if (el) {
        el.textContent = "● Daemon active";
        el.className   = "daemon-status ok";
      }
      const cnt = document.getElementById("daemon-count");
      if (cnt) cnt.textContent = d.threats_total || 0;
    }
  } catch (e) {
    const el = document.getElementById("daemon-status");
    if (el) el.textContent = "● Daemon offline";
  }
}

function updateUI() {
  const dot  = document.getElementById("dot");
  const text = document.getElementById("status-text");
  const btn  = document.getElementById("toggle-btn");
  if (!dot || !text || !btn) return;

  if (isActive) {
    dot.className    = "status-dot";
    text.textContent = "Active — Protecting you";
    btn.textContent  = "DISABLE";
    btn.className    = "toggle-btn";
  } else {
    dot.className    = "status-dot off";
    text.textContent = "Shield disabled";
    btn.textContent  = "ENABLE";
    btn.className    = "toggle-btn off";
  }
}

async function toggleShield() {
  try {
    const r = await chrome.runtime.sendMessage({ type: "toggleShield" });
    isActive = r.shieldActive;
    updateUI();
  } catch (e) {
    console.error("Toggle error:", e);
  }
}

async function clearCount() {
  try {
    await chrome.runtime.sendMessage({ type: "clearCount" });
    const el = document.getElementById("blocked-count");
    if (el) el.textContent = "0";
  } catch (e) {
    console.error("Clear error:", e);
  }
}

async function openDashboard() {
  await chrome.tabs.create({ url: "http://localhost:8766" });
  window.close();
}

async function checkCurrentPage() {
  try {
    const [tab] = await chrome.tabs.query({
      active: true, currentWindow: true });
    if (!tab?.url) return;

    const el = document.getElementById("status-text");

    const r = await fetch(
      `http://localhost:8766/check?url=${encodeURIComponent(tab.url)}`,
      { signal: AbortSignal.timeout(3000) });
    const d = await r.json();

    if (el) {
      el.textContent = d.safe
        ? "✓ This page is safe"
        : "⚠ Threat: " + (d.reason || "malicious").slice(0, 25);
    }
  } catch (e) {
    const el = document.getElementById("status-text");
    if (el) el.textContent = "Cannot reach daemon";
  }
}

// Wire up buttons after DOM loads
document.addEventListener("DOMContentLoaded", () => {
  init();

  const toggleBtn = document.getElementById("toggle-btn");
  if (toggleBtn) toggleBtn.addEventListener("click", toggleShield);

  const clearBtn = document.getElementById("btn-clear");
  if (clearBtn) clearBtn.addEventListener("click", clearCount);

  const dashBtn = document.getElementById("btn-dashboard");
  if (dashBtn) dashBtn.addEventListener("click", openDashboard);

  const checkBtn = document.getElementById("btn-check");
  if (checkBtn) checkBtn.addEventListener("click", checkCurrentPage);
});
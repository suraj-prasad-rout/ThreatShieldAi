/**
 * ThreatShield AI — Chrome Extension Background Worker
 * Intercepts all navigation and downloads, checks against ThreatShield daemon.
 */

const DAEMON_URL   = "http://localhost:8766";
const BYPASS_HOSTS = new Set([
  "urlhaus.abuse.ch","abuse.ch","virustotal.com",
  "phishtank.com","hybrid-analysis.com","any.run",
  "threatfox.abuse.ch","bazaar.abuse.ch","malwarebytes.com",
  "localhost","127.0.0.1"
]);
const DANGER_EXTS  = new Set([
  ".exe",".msi",".bat",".cmd",".ps1",".vbs",".js",
  ".jar",".com",".scr",".pif",".hta",".wsf",".dll",
  ".zip",".rar",".7z",".gz",".tar"
]);

let shieldActive   = true;
let blockedCount   = 0;
let pendingChecks  = new Map();

// ── load saved state ─────────────────────────────────────────────────────────
chrome.storage.local.get(["shieldActive","blockedCount"], (data) => {
  if (data.shieldActive !== undefined) shieldActive = data.shieldActive;
  if (data.blockedCount !== undefined) blockedCount  = data.blockedCount;
  updateBadge();
});

// ── URL interception ──────────────────────────────────────────────────────────
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (!shieldActive) return;
  if (details.frameId !== 0) return;

  const url  = details.url;
  const host = new URL(url).hostname;

  if (!url.startsWith("http")) return;
  if (BYPASS_HOSTS.has(host))  return;
  if (url.includes("localhost:8766")) return;

  // skip if already a warning/blocked page
  if (url.includes("localhost:8766/warning") ||
      url.includes("localhost:8766/blocked")) return;

  try {
    const resp = await fetch(
      `${DAEMON_URL}/check?url=${encodeURIComponent(url)}`,
      { signal: AbortSignal.timeout(3000) });

    if (!resp.ok) return;
    const data = await resp.json();

    if (!data.safe) {
      blockedCount++;
      chrome.storage.local.set({ blockedCount });
      updateBadge();

      // redirect to warning page
      chrome.tabs.update(details.tabId, {
        url: `${DAEMON_URL}/warning.html` +
             `?url=${encodeURIComponent(url)}` +
             `&reason=${encodeURIComponent(data.reason || "Malicious site")}`
      });

      showNotification(
        "⚠ Threat Blocked",
        `ThreatShield blocked: ${host}`);
    }
  } catch (e) {
    // daemon not running — fail open (don't block)
  }
});

// ── download interception ─────────────────────────────────────────────────────
chrome.downloads.onCreated.addListener(async (item) => {
  if (!shieldActive) return;

  const url = item.url || item.finalUrl || "";
  if (!url) return;

  // check extension
  let isDangerous = false;
  try {
    const pathname = new URL(url).pathname.toLowerCase();
    isDangerous = [...DANGER_EXTS].some(ext => pathname.endsWith(ext));
  } catch (e) {
    const lower = url.toLowerCase();
    isDangerous = [...DANGER_EXTS].some(ext => lower.includes(ext));
  }

  if (!isDangerous) return;

  try {
    const resp = await fetch(
      `${DAEMON_URL}/check?url=${encodeURIComponent(url)}`,
      { signal: AbortSignal.timeout(5000) });

    if (!resp.ok) return;
    const data = await resp.json();

    if (!data.safe) {
      // cancel the download immediately
      chrome.downloads.cancel(item.id);
      blockedCount++;
      chrome.storage.local.set({ blockedCount });
      updateBadge();

      showNotification(
        "🚫 Download Blocked",
        `Malicious file blocked: ${url.split("/").pop().slice(0,40)}`);

      // open warning in new tab
      chrome.tabs.create({
        url: `${DAEMON_URL}/warning.html` +
             `?url=${encodeURIComponent(url)}` +
             `&reason=${encodeURIComponent(data.reason || "Malicious download")}`
      });
    }
  } catch (e) {
    // daemon not running
  }
});

// ── badge ─────────────────────────────────────────────────────────────────────
function updateBadge() {
  if (!shieldActive) {
    chrome.action.setBadgeText({ text: "OFF" });
    chrome.action.setBadgeBackgroundColor({ color: "#555" });
    return;
  }
  if (blockedCount > 0) {
    chrome.action.setBadgeText({
      text: blockedCount > 99 ? "99+" : String(blockedCount)
    });
    chrome.action.setBadgeBackgroundColor({ color: "#e8503a" });
  } else {
    chrome.action.setBadgeText({ text: "ON" });
    chrome.action.setBadgeBackgroundColor({ color: "#1d9e75" });
  }
}

// ── notification ──────────────────────────────────────────────────────────────
function showNotification(title, message) {
  chrome.notifications.create({
    type:    "basic",
    iconUrl: "icons/icon48.png",
    title,
    message,
  });
}

// ── messages from popup ───────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, respond) => {
  if (msg.type === "getStatus") {
    respond({ shieldActive, blockedCount });
  } else if (msg.type === "toggleShield") {
    shieldActive = !shieldActive;
    chrome.storage.local.set({ shieldActive });
    updateBadge();
    respond({ shieldActive });
  } else if (msg.type === "clearCount") {
    blockedCount = 0;
    chrome.storage.local.set({ blockedCount });
    updateBadge();
    respond({ ok: true });
  }
  return true;
});

updateBadge();

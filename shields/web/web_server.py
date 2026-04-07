"""
ThreatShield AI — Local HTTP Server
Flow: Warning page → Block → DNS Block page → Unblock → Warning page again
"""
import json
import threading
import subprocess
import ctypes
import os
import tempfile
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from core.logger import get_logger

log = get_logger("web_server")
PORT = 8766
HOSTS_FILE = r"C:\Windows\System32\drivers\etc\hosts"

SECURITY_SITES = {
    "urlhaus.abuse.ch", "abuse.ch", "virustotal.com", "phishtank.com",
    "phishtank.org", "hybrid-analysis.com", "any.run", "joesandbox.com",
    "threatfox.abuse.ch", "bazaar.abuse.ch", "malwarebytes.com",
}


def _is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def _block_dns(domain: str) -> dict:
    entry_1 = f"127.0.0.1 {domain}  # ThreatShield-blocked"
    entry_2 = f"127.0.0.1 www.{domain}  # ThreatShield-blocked"
    try:
        with open(HOSTS_FILE, "r", encoding="utf-8") as f:
            if f"{domain}  # ThreatShield-blocked" in f.read():
                return {"success": True, "method": "already_blocked"}
    except Exception:
        pass
    if _is_admin():
        try:
            with open(HOSTS_FILE, "a", encoding="utf-8") as f:
                f.write(f"\n{entry_1}\n{entry_2}\n")
            subprocess.run(["ipconfig", "/flushdns"],
                           capture_output=True, timeout=5)
            log.info(f"DNS blocked directly: {domain}")
            return {"success": True, "method": "direct"}
        except Exception as e:
            log.error(f"Direct DNS block failed: {e}")
    try:
        ps = f"""$hosts = '{HOSTS_FILE}'
Add-Content -Path $hosts -Value "`n{entry_1}" -Encoding UTF8
Add-Content -Path $hosts -Value "`n{entry_2}" -Encoding UTF8
ipconfig /flushdns | Out-Null
"""
        tmp = tempfile.NamedTemporaryFile(
            suffix=".ps1", delete=False, mode="w", encoding="utf-8",
            dir=os.environ.get("TEMP", "C:\\Temp"))
        tmp.write(ps)
        tmp.close()
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", "powershell.exe",
            f'-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{tmp.name}"',
            None, 0)

        def _clean():
            import time
            time.sleep(5)
            try:
                os.unlink(tmp.name)
            except Exception:
                pass
        threading.Thread(target=_clean, daemon=True).start()
        if ret > 32:
            log.info(f"DNS block via UAC: {domain}")
            return {"success": True, "method": "uac"}
        return {"success": False, "method": "uac_denied"}
    except Exception as e:
        return {"success": False, "method": "error", "error": str(e)}


def _unblock_dns(domain: str) -> bool:
    try:
        with open(HOSTS_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
        new_lines = [l for l in lines
                     if not (domain in l and "ThreatShield-blocked" in l)]
        if _is_admin():
            with open(HOSTS_FILE, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
            subprocess.run(["ipconfig", "/flushdns"],
                           capture_output=True, timeout=5)
            log.info(f"DNS unblocked: {domain}")
            return True
        else:
            ps = f"""$hosts = '{HOSTS_FILE}'
$lines = Get-Content $hosts
$filtered = $lines | Where-Object {{ -not ($_ -match [regex]::Escape('{domain}') -and $_ -match 'ThreatShield-blocked') }}
Set-Content -Path $hosts -Value $filtered -Encoding UTF8
ipconfig /flushdns | Out-Null
"""
            tmp = tempfile.NamedTemporaryFile(
                suffix=".ps1", delete=False, mode="w", encoding="utf-8")
            tmp.write(ps)
            tmp.close()
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", "powershell.exe",
                f'-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{tmp.name}"',
                None, 0)
            return True
    except Exception as e:
        log.error(f"DNS unblock error: {e}")
        return False


class _Handler(BaseHTTPRequestHandler):
    storage = None
    web_shield = None

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        try:
            parsed = urlparse(self.path)

            # ── /check ────────────────────────────────────────────────────
            if parsed.path == "/check":
                params = parse_qs(parsed.query)
                url = params.get("url", [""])[0]
                if url:
                    try:
                        h = urlparse(url).hostname or ""
                        parts = h.split(".")
                        parent = ".".join(parts[-2:]) if len(parts) >= 2 else h
                        if h in SECURITY_SITES or parent in SECURITY_SITES:
                            self._json(
                                {"safe": True, "source": "security_site"})
                            return
                    except Exception:
                        pass
                    self._json(self.web_shield.check_url(url))
                else:
                    self._json({"safe": True})

            # ── /status ───────────────────────────────────────────────────
            elif parsed.path == "/status":
                self._json({
                    "status":        "active",
                    "is_admin":      _is_admin(),
                    "threats_found": len(self.storage.threat_log),
                    "shields":       self.storage.config.get("active_shields", []),
                })

            # ── /block ────────────────────────────────────────────────────
            elif parsed.path == "/block":
                params = parse_qs(parsed.query)
                domain = params.get("domain", [""])[0]
                url = params.get("url", [""])[0]
                if domain:
                    import time
                    # add to blocklist
                    self.storage.update_learned("blocked_senders", domain)
                    # mark in url cache
                    cache = self.storage.url_cache
                    for scheme in ["http", "https"]:
                        cache[f"{scheme}://{domain}"] = {
                            "safe": False, "checked_at": time.time()}
                    self.storage.save("url_cache.json", cache)
                    # DNS block
                    dns = _block_dns(domain)
                    log.info(f"Blocked: {domain} dns={dns['method']}")
                    self._json({
                        "success":    True,
                        "domain":     domain,
                        "dns_blocked": dns["success"],
                        "dns_method": dns["method"],
                        "is_admin":   _is_admin(),
                        # send back the original URL so frontend can redirect
                        "original_url": url,
                    })
                else:
                    self._json({"success": False})

            # ── /unblock ──────────────────────────────────────────────────
            elif parsed.path == "/unblock":
                params = parse_qs(parsed.query)
                domain = params.get("domain", [""])[0]
                # original URL to redirect back to
                url = params.get("url",    [""])[0]
                if domain:
                    ok = _unblock_dns(domain)
                    # remove from blocklist
                    p = self.storage.learned_patterns
                    p["blocked_senders"] = [
                        b for b in p.get("blocked_senders", [])
                        if domain not in b]
                    self.storage.save("learned_patterns.json", p)
                    # remove from url cache completely
                    cache = {k: v for k, v in self.storage.url_cache.items()
                             if domain not in k}
                    self.storage.save("url_cache.json", cache)
                    log.info(f"Unblocked: {domain}")
                    self._json({
                        "success":      ok,
                        "domain":       domain,
                        # frontend uses this to redirect to warning page
                        "redirect_url": url or f"http://{domain}",
                    })
                else:
                    self._json({"success": False})

            # ── /blocked.html ─────────────────────────────────────────────
            elif parsed.path == "/blocked.html":
                params = parse_qs(parsed.query)
                domain = params.get("domain", ["unknown"])[0]
                url = params.get("url",    [f"http://{domain}"])[0]
                html = _build_blocked_html(domain, url)
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self._cors_headers()
                self.end_headers()
                self.wfile.write(html.encode("utf-8"))

            # ── /warning.html ─────────────────────────────────────────────
            elif parsed.path == "/warning.html":
                params = parse_qs(parsed.query)
                url = params.get("url",    ["unknown"])[0]
                reason = params.get("reason", ["Malicious site detected"])[0]
                html = _build_warning_html(url, reason)
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self._cors_headers()
                self.end_headers()
                self.wfile.write(html.encode("utf-8"))

            else:
                self.send_response(404)
                self.end_headers()

        except (ConnectionAbortedError, BrokenPipeError):
            pass
        except Exception as e:
            log.debug(f"Request error: {e}")

    def do_OPTIONS(self):
        try:
            self._send_cors()
        except:
            pass

    def _json(self, data):
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self._cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _send_cors(self):
        self.send_response(200)
        self._cors_headers()
        self.end_headers()

    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")


# ── DNS Block page ────────────────────────────────────────────────────────────
def _build_blocked_html(domain: str, original_url: str) -> str:
    """
    Shown when user revisits a blocked domain.
    Unblock button → removes DNS block → redirects to WARNING page
    (not directly to the site — user still has to consent on warning page)
    """
    safe_url = original_url.replace('"', '%22').replace('<', '&lt;')
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>ThreatShield AI — Access Blocked</title>
<style>
  *{{margin:0;padding:0;box-sizing:border-box;}}
  body{{font-family:'Segoe UI',sans-serif;background:#0a0e0d;color:#c8ddd8;
    min-height:100vh;display:flex;align-items:center;justify-content:center;}}
  .card{{background:#0f1512;border-top:4px solid #e8503a;border-radius:16px;
    padding:52px 44px;max-width:540px;width:92%;text-align:center;}}
  .shield{{font-size:64px;margin-bottom:20px;}}
  .badge{{display:inline-block;background:#2a0808;color:#e8503a;
    border:1px solid #3a1a1a;border-radius:4px;padding:4px 14px;font-size:11px;
    font-family:Consolas,monospace;letter-spacing:.15em;margin-bottom:16px;}}
  h1{{color:#e8503a;font-size:26px;font-weight:700;margin-bottom:8px;}}
  .subtitle{{color:#5a7a74;font-size:14px;margin-bottom:24px;}}
  .info-box{{background:#0d1a14;border:1px solid #1a2e28;border-radius:10px;
    padding:20px;margin-bottom:28px;text-align:left;}}
  .info-row{{display:flex;justify-content:space-between;align-items:center;
    padding:6px 0;border-bottom:1px solid #111a17;}}
  .info-row:last-child{{border-bottom:none;}}
  .info-label{{font-family:Consolas,monospace;font-size:12px;color:#5a7a74;
    text-transform:uppercase;letter-spacing:.05em;}}
  .info-val{{font-size:13px;color:#c8ddd8;font-weight:600;}}
  .info-val.red{{color:#e8503a;}} .info-val.amber{{color:#f0a500;}}
  .buttons{{display:flex;gap:12px;justify-content:center;flex-wrap:wrap;}}
  .btn-home{{background:#1d9e75;color:#fff;border:none;border-radius:8px;
    padding:12px 28px;font-size:14px;font-weight:700;cursor:pointer;}}
  .btn-home:hover{{background:#25c791;}}
  .btn-unblock{{background:transparent;color:#5a7a74;border:1px solid #2a4a44;
    border-radius:8px;padding:12px 24px;font-size:13px;cursor:pointer;}}
  .btn-unblock:hover{{color:#c8ddd8;border-color:#5a7a74;}}
  .btn-unblock:disabled{{opacity:.4;cursor:not-allowed;}}
  #msg{{display:none;margin-top:14px;font-size:12px;
    font-family:Consolas,monospace;padding:10px;border-radius:6px;
    background:#0a1f1a;border:1px solid #1a2e28;color:#25c791;}}
  .footer{{margin-top:28px;font-size:11px;color:#1a2e28;font-family:Consolas,monospace;}}
</style>
</head>
<body>
<div class="card">
  <div class="shield">&#128683;</div>
  <div class="badge">DNS FILTER — ThreatShield AI</div>
  <h1>Access to this site is blocked</h1>
  <p class="subtitle">This domain was blocked due to malicious activity</p>
  <div class="info-box">
    <div class="info-row">
      <span class="info-label">Domain</span>
      <span class="info-val red">{domain}</span>
    </div>
    <div class="info-row">
      <span class="info-label">Reason</span>
      <span class="info-val amber">Malware / Phishing</span>
    </div>
    <div class="info-row">
      <span class="info-label">Action</span>
      <span class="info-val">Blocked by DNS filter</span>
    </div>
    <div class="info-row">
      <span class="info-label">Protection</span>
      <span class="info-val">ThreatShield AI</span>
    </div>
  </div>
  <div class="buttons">
    <button class="btn-home" onclick="goHome()">Go Back to Safety</button>
    <button class="btn-unblock" id="unblockBtn" onclick="unblock()">
      Unblock This Domain
    </button>
  </div>
  <div id="msg"></div>
  <p class="footer">ThreatShield AI &mdash; DNS filter active on this device</p>
</div>
<script>
const DOMAIN       = "{domain}";
const ORIGINAL_URL = "{safe_url}";
const DAEMON       = "http://localhost:8766";
const WARNING_PAGE = DAEMON + "/warning.html";

function goHome() {{
  window.location.replace("about:blank");
  setTimeout(() => window.close(), 100);
}}

function unblock() {{
  const btn = document.getElementById("unblockBtn");
  const msg = document.getElementById("msg");
  btn.disabled    = true;
  btn.textContent = "Unblocking...";

  fetch(DAEMON + "/unblock?domain=" + encodeURIComponent(DOMAIN) +
        "&url=" + encodeURIComponent(ORIGINAL_URL))
    .then(r => r.json())
    .then(data => {{
      if (data.success) {{
        msg.style.display = "block";
        msg.textContent   =
          DOMAIN + " unblocked. Redirecting to warning page...";
        // ── KEY BEHAVIOUR ──
        // After unblocking, redirect to WARNING page (not directly to site)
        // User must still consent on the warning page before visiting
        setTimeout(() => {{
          const warnUrl =
            WARNING_PAGE +
            "?url=" + encodeURIComponent(data.redirect_url || ORIGINAL_URL) +
            "&reason=" + encodeURIComponent(
              "You unblocked this domain. It was previously identified as " +
              "Malware / Phishing. Proceed with caution.");
          window.location.href = warnUrl;
        }}, 1500);
      }} else {{
        msg.style.display = "block";
        msg.style.color   = "#f0a500";
        msg.textContent   =
          "Unblock failed. Try running ThreatShield as Administrator.";
        btn.disabled    = false;
        btn.textContent = "Unblock This Domain";
      }}
    }})
    .catch(() => {{
      msg.style.display = "block";
      msg.style.color   = "#e8503a";
      msg.textContent   = "Could not reach daemon. Is ThreatShield running?";
      btn.disabled    = false;
      btn.textContent = "Unblock This Domain";
    }});
}}
</script>
</body>
</html>"""


# ── Warning page ──────────────────────────────────────────────────────────────
def _build_warning_html(url: str, reason: str) -> str:
    safe_url = url.replace('"', '%22').replace(
        '<', '&lt;').replace('>', '&gt;')
    safe_reason = reason.replace('<', '&lt;').replace('>', '&gt;')
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>ThreatShield AI — Site Blocked</title>
<style>
  *{{margin:0;padding:0;box-sizing:border-box;}}
  body{{font-family:'Segoe UI',sans-serif;background:#0a0e0d;color:#c8ddd8;
    min-height:100vh;display:flex;align-items:center;justify-content:center;}}
  .card{{background:#0f1512;border:1px solid #e8503a;border-radius:16px;
    padding:48px 40px;max-width:560px;width:92%;text-align:center;}}
  .icon{{width:72px;height:72px;background:#2a0808;border:2px solid #e8503a;
    border-radius:50%;display:flex;align-items:center;justify-content:center;
    font-size:32px;margin:0 auto 20px;}}
  .badge{{display:inline-block;background:#2a0808;color:#e8503a;
    border:1px solid #3a1a1a;border-radius:4px;padding:4px 12px;font-size:11px;
    font-family:Consolas,monospace;letter-spacing:.1em;margin-bottom:12px;}}
  h1{{color:#e8503a;font-size:24px;font-weight:700;margin-bottom:16px;}}
  .url-box{{background:#1a0d0d;border:1px solid #3a1a1a;border-radius:8px;
    padding:12px 16px;font-family:Consolas,monospace;font-size:13px;
    color:#e8503a;word-break:break-all;margin:0 0 12px;}}
  .reason{{font-size:14px;color:#5a7a74;margin-bottom:28px;line-height:1.6;}}
  .buttons{{display:flex;gap:12px;justify-content:center;flex-wrap:wrap;margin-bottom:16px;}}
  .btn-safe{{background:#1d9e75;color:#fff;border:none;border-radius:8px;
    padding:12px 28px;font-size:15px;font-weight:700;cursor:pointer;}}
  .btn-safe:hover{{background:#25c791;}}
  .btn-block{{background:#2a0808;color:#e8503a;border:1px solid #3a1a1a;
    border-radius:8px;padding:12px 28px;font-size:14px;font-weight:600;cursor:pointer;}}
  .btn-block:hover{{background:#3a1010;}}
  .btn-block:disabled{{opacity:.5;cursor:not-allowed;}}
  .btn-proceed{{background:transparent;color:#2a4a44;border:1px solid #1a2e28;
    border-radius:8px;padding:8px 20px;font-size:12px;cursor:pointer;}}
  .btn-proceed:hover{{color:#5a7a74;border-color:#2a4a44;}}
  .btn-proceed.warn{{color:#f0a500;border-color:#854F0B;}}
  #msg{{display:none;margin-top:14px;font-size:13px;font-family:Consolas,monospace;
    padding:10px;border-radius:6px;background:#0a1f1a;border:1px solid #1a2e28;}}
  .footer{{margin-top:20px;font-size:11px;color:#1a2e28;font-family:Consolas,monospace;}}
</style>
</head>
<body>
<div class="card">
  <div class="icon">&#9940;</div>
  <div class="badge">DANGEROUS SITE DETECTED</div>
  <h1>Dangerous Site Blocked</h1>
  <div class="url-box">{safe_url}</div>
  <p class="reason">{safe_reason}</p>
  <div class="buttons">
    <button class="btn-safe" onclick="goHome()">Go Back to Safety</button>
    <button class="btn-block" id="blockBtn" onclick="blockDomain()">
      Block This Domain
    </button>
  </div>
  <button class="btn-proceed" id="proceedBtn" onclick="proceedAnyway()">
    I understand the risk — proceed anyway
  </button>
  <div id="msg"></div>
  <p class="footer">ThreatShield AI &mdash; all data stored locally</p>
</div>
<script>
const SITE_URL = "{safe_url}";
const DAEMON   = "http://localhost:8766";
let   clicks   = 0;

function showMsg(text, color) {{
  const el = document.getElementById("msg");
  el.style.display = "block";
  el.style.color   = color || "#25c791";
  el.textContent   = text;
}}

function goHome() {{
  window.location.replace("about:blank");
  setTimeout(() => window.close(), 100);
}}

function blockDomain() {{
  const btn = document.getElementById("blockBtn");
  btn.disabled    = true;
  btn.textContent = "Blocking...";
  try {{
    const domain = new URL(SITE_URL).hostname;
    fetch(DAEMON + "/block?domain=" + encodeURIComponent(domain) +
          "&url=" + encodeURIComponent(SITE_URL))
      .then(r => r.json())
      .then(data => {{
        if (data.dns_method === "direct") {{
          showMsg("Blocked at DNS level — " + domain +
            " cannot load on this device.", "#25c791");
        }} else if (data.dns_method === "uac") {{
          showMsg("Windows security prompt appeared. " +
            "Click YES to enable DNS-level blocking.", "#f0a500");
        }} else if (data.dns_method === "already_blocked") {{
          showMsg(domain + " is already DNS blocked.", "#25c791");
        }} else {{
          showMsg("Blocked locally. Run as Administrator for " +
            "automatic DNS blocking.", "#f0a500");
        }}
        btn.textContent = "Blocked";
        // redirect to DNS block page after 2 seconds
        setTimeout(() => {{
          window.location.href =
            DAEMON + "/blocked.html" +
            "?domain=" + encodeURIComponent(domain) +
            "&url="    + encodeURIComponent(SITE_URL);
        }}, 2000);
      }})
      .catch(() => {{
        showMsg("Blocked locally.", "#f0a500");
        setTimeout(goHome, 2000);
      }});
  }} catch(e) {{
    showMsg("Error: " + e.message, "#e8503a");
  }}
}}

function proceedAnyway() {{
  clicks++;
  const btn = document.getElementById("proceedBtn");
  if (clicks === 1) {{
    btn.textContent = "Are you sure? Click again — this site is dangerous";
    btn.className   = "btn-proceed warn";
  }} else {{
    window.location.href = SITE_URL;
  }}
}}
</script>
</body>
</html>"""


def _cleanup_old_temp_files():
    """Remove leftover ThreatShield temp PS1 files from previous runs."""
    try:
        import glob
        import time as _t
        temp_dir = os.environ.get("TEMP", "C:\\Temp")
        for f in glob.glob(os.path.join(temp_dir, "tmp*.ps1")):
            try:
                # only delete if older than 60 seconds
                if _t.time() - os.path.getmtime(f) > 60:
                    os.unlink(f)
            except Exception:
                pass
    except Exception:
        pass


def start_server(storage, web_shield):
    _Handler.storage = storage
    _Handler.web_shield = web_shield
    server = HTTPServer(("localhost", PORT), _Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    is_admin = _is_admin()
    log.info(
        f"Web server running on http://localhost:{PORT} "
        f"[{'ADMIN' if is_admin else 'no admin — UAC needed for DNS'}]")
    return server

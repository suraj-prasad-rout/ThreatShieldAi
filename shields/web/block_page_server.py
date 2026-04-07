"""
ThreatShield AI — Block Page HTTP Server
Runs on 127.0.0.1:80
When DNS server returns 127.0.0.1 for a blocked domain,
this server handles the HTTP request and shows the block page.
This is exactly how Pi-hole works.
"""
import threading
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from core.logger import get_logger

log = get_logger("block_page")
PORT = 80


class _BlockPageHandler(BaseHTTPRequestHandler):
    storage = None

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        try:
            # get the domain that was blocked from Host header
            host   = self.headers.get("Host", "unknown").split(":")[0]
            parsed = urlparse(self.path)

            if parsed.path == "/unblock":
                params = parse_qs(parsed.query)
                domain = params.get("domain", [host])[0]
                self._unblock(domain)
                return

            # show the block page
            self._serve_block_page(host)

        except (ConnectionAbortedError, BrokenPipeError):
            pass
        except Exception as e:
            log.debug(f"Block page error: {e}")

    def _serve_block_page(self, domain: str):
        html = _build_block_page(domain)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def _unblock(self, domain: str):
        try:
            # remove from blocklist
            p = self.storage.learned_patterns
            p["blocked_senders"] = [
                b for b in p.get("blocked_senders", [])
                if domain not in b]
            self.storage.save("learned_patterns.json", p)

            # remove from hosts file
            hosts = r"C:\Windows\System32\drivers\etc\hosts"
            with open(hosts, "r", encoding="utf-8") as f:
                lines = f.readlines()
            new_lines = [l for l in lines
                         if not (domain in l and "ThreatShield-blocked" in l)]
            with open(hosts, "w", encoding="utf-8") as f:
                f.writelines(new_lines)

            import subprocess
            subprocess.run(["ipconfig", "/flushdns"],
                           capture_output=True, timeout=5)
            log.info(f"Unblocked via block page: {domain}")

            # redirect to the domain now that it's unblocked
            self.send_response(302)
            self.send_header("Location", f"http://{domain}")
            self.end_headers()
        except Exception as e:
            log.error(f"Unblock error: {e}")
            self._serve_block_page(domain)


def _build_block_page(domain: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Access Blocked — ThreatShield AI</title>
<style>
  *{{margin:0;padding:0;box-sizing:border-box;}}
  body{{
    font-family:'Segoe UI',sans-serif;
    background:#0a0e0d;color:#c8ddd8;
    min-height:100vh;display:flex;
    align-items:center;justify-content:center;
  }}
  .card{{
    background:#0f1512;
    border-top:4px solid #e8503a;
    border-radius:16px;padding:52px 44px;
    max-width:540px;width:92%;text-align:center;
    box-shadow:0 0 60px rgba(232,80,58,0.1);
  }}
  .shield{{font-size:64px;margin-bottom:20px;}}
  .badge{{
    display:inline-block;background:#2a0808;color:#e8503a;
    border:1px solid #3a1a1a;border-radius:4px;
    padding:4px 14px;font-size:11px;
    font-family:Consolas,monospace;letter-spacing:.15em;
    margin-bottom:16px;text-transform:uppercase;
  }}
  h1{{color:#e8503a;font-size:26px;font-weight:700;margin-bottom:8px;}}
  .subtitle{{color:#5a7a74;font-size:14px;margin-bottom:24px;}}
  .info-box{{
    background:#0d1a14;border:1px solid #1a2e28;
    border-radius:10px;padding:20px;margin-bottom:28px;text-align:left;
  }}
  .info-row{{
    display:flex;justify-content:space-between;
    align-items:center;padding:6px 0;
    border-bottom:1px solid #111a17;
  }}
  .info-row:last-child{{border-bottom:none;}}
  .info-label{{
    font-family:Consolas,monospace;font-size:12px;
    color:#5a7a74;text-transform:uppercase;letter-spacing:.05em;
  }}
  .info-val{{font-size:13px;color:#c8ddd8;font-weight:600;}}
  .info-val.red{{color:#e8503a;}}
  .info-val.amber{{color:#f0a500;}}
  .buttons{{
    display:flex;gap:12px;justify-content:center;flex-wrap:wrap;
  }}
  .btn-home{{
    background:#1d9e75;color:#fff;border:none;
    border-radius:8px;padding:12px 28px;
    font-size:14px;font-weight:700;cursor:pointer;
    text-decoration:none;display:inline-block;
  }}
  .btn-home:hover{{background:#25c791;}}
  .btn-unblock{{
    background:transparent;color:#5a7a74;
    border:1px solid #2a4a44;border-radius:8px;
    padding:12px 24px;font-size:13px;cursor:pointer;
    text-decoration:none;display:inline-block;
  }}
  .btn-unblock:hover{{color:#c8ddd8;border-color:#5a7a74;}}
  .footer{{
    margin-top:28px;font-size:11px;
    color:#1a2e28;font-family:Consolas,monospace;
  }}
</style>
</head>
<body>
<div class="card">
  <div class="shield">&#128683;</div>
  <div class="badge">DNS Filter — ThreatShield AI</div>
  <h1>Access to this site is blocked</h1>
  <p class="subtitle">This domain has been identified as dangerous</p>

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
      <span class="info-val">ThreatShield AI — Local DNS</span>
    </div>
  </div>

  <div class="buttons">
    <a class="btn-home" href="about:blank">Go Back to Safety</a>
    <a class="btn-unblock" href="/unblock?domain={domain}">
      Unblock This Domain
    </a>
  </div>

  <p class="footer">
    ThreatShield AI &mdash; DNS filter active on this device
  </p>
</div>
</body>
</html>"""


def start_block_page_server(storage):
    _BlockPageHandler.storage = storage
    try:
        server = HTTPServer(("127.0.0.1", PORT), _BlockPageHandler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        log.info(f"Block page server running on http://127.0.0.1:{PORT}")
        return True
    except PermissionError:
        log.warning(
            "Block page server needs Administrator (port 80). "
            "Run ThreatShield as Administrator.")
        return False
    except Exception as e:
        log.error(f"Block page server failed: {e}")
        return False

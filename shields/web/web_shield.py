"""
ThreatShield AI — Web Shield
Checks URLs against local cache first, then VirusTotal.
Called by the local HTTP server when Chrome extension sends a request.
Only active when browser makes requests — zero idle resource usage.
"""
import time
import requests
import base64
from urllib.parse import urlparse
from core.logger import get_logger

log = get_logger("web_shield")
VT_URL = "https://www.virustotal.com/api/v3/urls"
CACHE_TTL = 86400  # 24 hours

# domains that are always safe — skip API call entirely
ALWAYS_SAFE_DOMAINS = {
    "google.com", "gmail.com", "youtube.com", "googleapis.com",
    "microsoft.com", "windows.com", "office.com", "live.com",
    "apple.com", "icloud.com", "amazon.com", "amazonaws.com",
    "cloudfront.net", "github.com", "stackoverflow.com",
    "linkedin.com", "twitter.com", "facebook.com", "instagram.com",
}


def _web_ai_summary(url: str, reason: str, score: float,
                    source: str, signals: list) -> str:
    """Generate AI analysis text for web threats."""
    lines = []
    domain = url.split("/")[2] if url.startswith("http") else url
    score_pct = int(score * 100)

    if source == "virustotal":
        lines.append(
            f"URL verified malicious by VirusTotal threat intelligence.")
    elif source == "urlhaus":
        lines.append(f"URL found in URLhaus malware distribution database.")
    elif source == "phishtank":
        lines.append(
            f"URL confirmed phishing site by PhishTank community database.")
    elif source == "blocklist":
        lines.append(
            f"Domain manually blocked by user — all traffic intercepted.")
    elif source == "heuristic":
        lines.append(f"Heuristic analysis flagged suspicious URL patterns.")

    if any("phish" in s.lower() for s in signals):
        lines.append(
            "Phishing site — designed to steal credentials or personal data.")
    if any("malware" in s.lower() or "download" in s.lower() for s in signals):
        lines.append("Malware distribution point — downloads dangerous files.")
    if any("suspicious tld" in s.lower() or ".xyz" in s.lower()
           or ".tk" in s.lower() for s in signals):
        lines.append("Suspicious TLD — commonly used by malicious actors.")
    if any("redirect" in s.lower() for s in signals):
        lines.append("Redirect chain detected — hides true destination.")
    if any("ip" in s.lower() and "direct" in s.lower() for s in signals):
        lines.append("Direct IP URL — bypasses domain reputation checks.")

    if score_pct >= 80:
        lines.append(
            f"HIGH THREAT (score {score_pct}/100) — Connection blocked automatically.")
    elif score_pct >= 50:
        lines.append(
            f"MEDIUM THREAT (score {score_pct}/100) — Proceed with extreme caution.")
    else:
        lines.append(
            f"LOW-MEDIUM THREAT (score {score_pct}/100) — Flagged for review.")

    return " | ".join(lines)


class WebShield:
    def __init__(self, storage, bus):
        self.storage = storage
        self.bus = bus

    def start(self):
        log.info("Web shield ready — listening for extension requests")

    def check_url(self, url: str) -> dict:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower().lstrip("www.")
            parts = domain.split(".")
            parent = ".".join(parts[-2:]) if len(parts) >= 2 else domain

            # ── always safe domains — instant response ────────────────────
            if parent in ALWAYS_SAFE_DOMAINS:
                return {"safe": True, "source": "trusted", "url": url}

            # ── blocked domains — instant block ───────────────────────────
            blocked = self.storage.learned_patterns.get("blocked_senders", [])
            if parent in blocked or domain in blocked:
                self.storage.log_threat({
                    "shield":     "web",
                    "url":        url,
                    "type":       "blocked_domain",
                    "reason":     f"Domain '{parent}' is on your block list",
                    "score":      0.9,
                    "action":     "dns_blocked",
                    "source":     "blocklist",
                    "signals":    ["Domain manually blocked by user"],
                    "ai_analysis": _web_ai_summary(
                        url, f"Domain '{parent}' blocked", 0.9,
                        "blocklist", ["Domain manually blocked by user"]),
                })
                self.bus.emit("threat_found", {"shield": "web", "url": url})
                return {
                    "safe":   False,
                    "source": "blocklist",
                    "reason": f"Domain '{parent}' is on your block list",
                    "url":    url,
                }

            # ── local cache — fast, no API call ───────────────────────────
            cached = self.storage.url_cache.get(url)
            if cached and (time.time() - cached["checked_at"]) < CACHE_TTL:
                result = {
                    "safe":   cached["safe"],
                    "source": "cache",
                    "url":    url,
                }
                if not cached["safe"]:
                    result["reason"] = "Previously identified as malicious"
                return result

            # ── VirusTotal API ────────────────────────────────────────────
            api_key = self.storage.config.get("virustotal_api_key", "")
            if not api_key:
                return {"safe": True, "source": "no_api_key", "url": url}

            url_id = base64.urlsafe_b64encode(
                url.encode()).decode().strip("=")
            r = requests.get(
                f"{VT_URL}/{url_id}",
                headers={"x-apikey": api_key},
                timeout=6,
            )

            if r.status_code == 200:
                attrs = r.json()["data"]["attributes"]
                stats = attrs["last_analysis_stats"]
                mal = stats.get("malicious", 0)
                sus = stats.get("suspicious", 0)
                is_safe = (mal + sus) == 0

                self.storage.cache_url(url, is_safe)

                if not is_safe:
                    det = mal + sus
                    # score: cap at 1.0, based on detections (max ~70 engines)
                    score = min(det / 10.0, 1.0)
                    _vt_sigs = [
                        f"{mal} malicious, {sus} suspicious detections on VirusTotal"]
                    self.storage.log_threat({
                        "shield":     "web",
                        "url":        url,
                        "type":       "malicious_url",
                        "reason":     f"Flagged by {det} security vendors",
                        "score":      score,
                        "action":     "blocked",
                        "source":     "virustotal",
                        "signals":    _vt_sigs,
                        "ai_analysis": _web_ai_summary(
                            url, f"Flagged by {det} vendors", score,
                            "virustotal", _vt_sigs),
                    })
                    self.bus.emit("threat_found", {
                        "shield": "web",
                        "url":    url,
                    })
                    log.warning(f"Malicious URL blocked: {url}")
                    return {
                        "safe":   False,
                        "source": "virustotal",
                        "reason": f"Flagged by {mal} security vendors",
                        "stats":  stats,
                        "url":    url,
                    }

                return {
                    "safe":   True,
                    "source": "virustotal",
                    "url":    url,
                }

            # VT returned non-200 — allow but cache nothing
            return {"safe": True, "source": "vt_unavailable", "url": url}

        except requests.Timeout:
            log.warning(f"VirusTotal timeout for {url}")
            return {"safe": True, "source": "timeout", "url": url}
        except Exception as e:
            log.error(f"Web shield error: {e}")
            return {"safe": True, "source": "error", "url": url}

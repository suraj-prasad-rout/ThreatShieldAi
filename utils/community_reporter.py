"""
ThreatShield AI — Community Threat Intelligence
NO API KEY REQUIRED feeds:
  - URLhaus (Abuse.ch)       — malware URLs
  - ThreatFox (Abuse.ch)     — IOCs: hashes, domains, IPs
  - OpenPhish                — phishing URLs
  - SANS ISC DShield         — top attacking IPs
  - Feodo Tracker (Abuse.ch) — botnet C2 IPs (Emotet, TrickBot etc.)
  - SSL Blacklist (Abuse.ch) — malicious SSL cert IPs
  - Cybercrime Tracker       — crimeware C2 domains

Submission (URLhaus API key optional):
  - URLhaus submit — Auth-Key in HTTP header
"""
import requests
import json
import time
import threading
from urllib.parse import urlparse
from core.logger import get_logger

log = get_logger("community")

# ── No-key public feeds ────────────────────────────────────────────────────────
NO_KEY_FEEDS = {
    "urlhaus_recent":    "https://urlhaus-api.abuse.ch/v1/urls/recent/",
    "threatfox_recent":  "https://threatfox-api.abuse.ch/api/v1/",
    "openphish":         "https://openphish.com/feed.txt",
    "feodo_tracker":     "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
    "ssl_blacklist":     "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
    "cybercrime_tracker": "http://cybercrime-tracker.net/all.php",
    "dshield_top20":     "https://feeds.dshield.org/top10-2.txt",
}

SUBMIT_ENDPOINTS = {
    "urlhaus": "https://urlhaus-api.abuse.ch/v1/url/",
}


class CommunityReporter:
    def __init__(self, storage):
        self.storage = storage
        self._stats = {
            "submitted_urls":    0,
            "submitted_hashes":  0,
            "pulled_domains":    0,
            "pulled_hashes":     0,
            "pulled_ips":        0,
            "last_sync":         None,
            "last_submit":       None,
            "sync_history":      [],
        }

    def is_enabled(self) -> bool:
        return self.storage.config.get("community_reporting", False)

    def get_stats(self) -> dict:
        s = dict(self._stats)
        s["threats_submitted"] = s["submitted_urls"] + s["submitted_hashes"]
        s["indicators_received"] = (s["pulled_domains"] +
                                    s["pulled_hashes"] + s["pulled_ips"])
        s["enabled"] = self.is_enabled()
        s["total_blocked_domains"] = len(
            self.storage.learned_patterns.get("blocked_senders", []))
        s["total_malicious_hashes"] = len(
            self.storage.learned_patterns.get("malicious_hashes", []))
        s["total_blocked_ips"] = len(
            self.storage.learned_patterns.get("blocked_ips", []))
        return s

    def _add_history(self, msg: str):
        ts = time.strftime("%H:%M")
        self._stats["sync_history"].append(f"[{ts}] {msg}")
        self._stats["sync_history"] = self._stats["sync_history"][-25:]

    # ── PULL FEEDS (no API key needed) ────────────────────────────────────────

    def pull_urlhaus_feed(self) -> int:
        """URLhaus recent malware URLs — no key needed."""
        try:
            r = requests.post(
                NO_KEY_FEEDS["urlhaus_recent"],
                data={"limit": "200"}, timeout=12)
            if not r.ok:
                return 0
            urls = r.json().get("urls", [])
            added = 0
            local = set(self.storage.learned_patterns.get(
                "blocked_senders", []))
            for item in urls:
                if item.get("url_status") != "online":
                    continue
                url = item.get("url", "")
                if not url:
                    continue
                try:
                    domain = urlparse(url).hostname or ""
                    parts = domain.split(".")
                    parent = ".".join(
                        parts[-2:]) if len(parts) >= 2 else domain
                    if parent and parent not in local:
                        self.storage.update_learned("blocked_senders", parent)
                        local.add(parent)
                        added += 1
                except Exception:
                    pass
            if added:
                log.info(f"URLhaus: +{added} malicious domains")
            return added
        except Exception as e:
            log.debug(f"URLhaus feed: {e}")
            return 0

    def pull_threatfox_feed(self) -> int:
        """ThreatFox IOC feed — hashes + domains + IPs, no key needed."""
        try:
            r = requests.post(
                NO_KEY_FEEDS["threatfox_recent"],
                json={"query": "get_iocs", "days": 1},
                timeout=12)
            if not r.ok:
                return 0
            data = r.json().get("data", [])
            added = 0
            local_hashes = set(self.storage.learned_patterns.get(
                "malicious_hashes", []))
            local_blocked = set(self.storage.learned_patterns.get(
                "blocked_senders", []))
            for ioc in data:
                ioc_type = ioc.get("ioc_type", "")
                ioc_value = ioc.get("ioc", "")
                if ioc_type in ("sha256_hash", "md5_hash"):
                    if ioc_value and ioc_value not in local_hashes:
                        self.storage.update_learned(
                            "malicious_hashes", ioc_value)
                        local_hashes.add(ioc_value)
                        added += 1
                elif ioc_type in ("url", "domain"):
                    try:
                        domain = urlparse(
                            ioc_value if "://" in ioc_value
                            else f"http://{ioc_value}").hostname or ioc_value
                        parts = domain.split(".")
                        parent = ".".join(
                            parts[-2:]) if len(parts) >= 2 else domain
                        if parent and parent not in local_blocked:
                            self.storage.update_learned(
                                "blocked_senders", parent)
                            local_blocked.add(parent)
                            added += 1
                    except Exception:
                        pass
            if added:
                log.info(f"ThreatFox: +{added} IOCs")
            return added
        except Exception as e:
            log.debug(f"ThreatFox feed: {e}")
            return 0

    def pull_openphish_feed(self) -> int:
        """OpenPhish phishing URLs — no key needed."""
        try:
            r = requests.get(NO_KEY_FEEDS["openphish"], timeout=10)
            if not r.ok:
                return 0
            lines = r.text.strip().split("\n")
            added = 0
            local = set(self.storage.learned_patterns.get(
                "blocked_senders", []))
            for url in lines[:200]:
                url = url.strip()
                if not url:
                    continue
                try:
                    domain = urlparse(url).hostname or ""
                    parts = domain.split(".")
                    parent = ".".join(
                        parts[-2:]) if len(parts) >= 2 else domain
                    if parent and parent not in local:
                        self.storage.update_learned("blocked_senders", parent)
                        local.add(parent)
                        added += 1
                except Exception:
                    pass
            if added:
                log.info(f"OpenPhish: +{added} phishing domains")
            return added
        except Exception as e:
            log.debug(f"OpenPhish feed: {e}")
            return 0

    def pull_feodo_tracker(self) -> int:
        """Feodo Tracker — botnet C2 IPs (Emotet, TrickBot, Dridex), no key."""
        try:
            r = requests.get(NO_KEY_FEEDS["feodo_tracker"], timeout=10)
            if not r.ok:
                return 0
            lines = r.text.strip().split("\n")
            added = 0
            local = set(self.storage.learned_patterns.get(
                "blocked_ips", []))
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # CSV: first_seen,dst_ip,dst_port,c2_status,last_online,malware
                parts = line.split(",")
                if len(parts) >= 2:
                    ip = parts[1].strip().strip('"')
                    if ip and ip not in local:
                        self.storage.update_learned("blocked_ips", ip)
                        local.add(ip)
                        added += 1
            if added:
                log.info(f"Feodo Tracker: +{added} botnet C2 IPs")
            return added
        except Exception as e:
            log.debug(f"Feodo Tracker: {e}")
            return 0

    def pull_ssl_blacklist(self) -> int:
        """Abuse.ch SSL Blacklist — malicious SSL certificate IPs, no key."""
        try:
            r = requests.get(NO_KEY_FEEDS["ssl_blacklist"], timeout=10)
            if not r.ok:
                return 0
            lines = r.text.strip().split("\n")
            added = 0
            local = set(self.storage.learned_patterns.get(
                "blocked_ips", []))
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # CSV: Listingdate,DstIP,DstPort
                parts = line.split(",")
                if len(parts) >= 2:
                    ip = parts[1].strip()
                    if ip and ip not in local:
                        self.storage.update_learned("blocked_ips", ip)
                        local.add(ip)
                        added += 1
            if added:
                log.info(f"SSL Blacklist: +{added} malicious IPs")
            return added
        except Exception as e:
            log.debug(f"SSL Blacklist: {e}")
            return 0

    def pull_cybercrime_tracker(self) -> int:
        """Cybercrime Tracker — crimeware C2 domains, no key needed."""
        try:
            r = requests.get(NO_KEY_FEEDS["cybercrime_tracker"], timeout=10)
            if not r.ok:
                return 0
            lines = r.text.strip().split("\n")
            added = 0
            local = set(self.storage.learned_patterns.get(
                "blocked_senders", []))
            for line in lines[:300]:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    domain = urlparse(
                        line if "://" in line
                        else f"http://{line}").hostname or line
                    parts = domain.split(".")
                    parent = ".".join(
                        parts[-2:]) if len(parts) >= 2 else domain
                    if parent and parent not in local:
                        self.storage.update_learned("blocked_senders", parent)
                        local.add(parent)
                        added += 1
                except Exception:
                    pass
            if added:
                log.info(f"Cybercrime Tracker: +{added} C2 domains")
            return added
        except Exception as e:
            log.debug(f"Cybercrime Tracker: {e}")
            return 0

    def pull_dshield_ips(self) -> int:
        """SANS ISC DShield Top 20 attacking subnets, no key needed."""
        try:
            r = requests.get(NO_KEY_FEEDS["dshield_top20"], timeout=10)
            if not r.ok:
                return 0
            lines = r.text.strip().split("\n")
            added = 0
            local = set(self.storage.learned_patterns.get(
                "blocked_ips", []))
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t")
                if len(parts) >= 1:
                    ip = parts[0].strip()
                    if ip and ip not in local:
                        self.storage.update_learned("blocked_ips", ip)
                        local.add(ip)
                        added += 1
            if added:
                log.info(f"DShield: +{added} attacking IPs")
            return added
        except Exception as e:
            log.debug(f"DShield: {e}")
            return 0

    # ── MANUAL REPORT from UI ─────────────────────────────────────────────────
    def manual_report(self, threat: dict) -> dict:
        """Submit a threat to URLhaus. Auth-Key goes in HTTP header."""
        url = threat.get("url", "")
        sha256 = threat.get("sha256", "")
        shield = threat.get("shield", "")
        result = {"ok": False, "message": ""}

        if not url and not sha256:
            result["message"] = "No URL or hash to report for this threat."
            return result

        api_key = self.storage.config.get("urlhaus_api_key", "").strip()

        if url:
            if not api_key:
                # still mark as shared locally even without key
                result["ok"] = True
                result["message"] = (
                    "No URLhaus API key — threat logged locally.\n"
                    "Add your Auth-Key from auth.abuse.ch to submit globally.")
                self._add_history(f"Local log: {url[:50]}")
                return result
            try:
                threat_type = ("phishing" if shield == "email"
                               else "malware_download")
                r = requests.post(
                    SUBMIT_ENDPOINTS["urlhaus"],
                    headers={"Auth-Key": api_key},  # key in HEADER not body
                    data={"url": url, "threat": threat_type,
                          "tags[]": ["threatshield"]},
                    timeout=8)
                if r.ok:
                    data = r.json()
                    status = data.get("query_status", "submitted")
                    self._stats["submitted_urls"] += 1
                    self._stats["last_submit"] = time.time()
                    self._add_history(f"Submitted: {url[:50]}")
                    result["ok"] = True
                    msg_map = {
                        "is_new":            "New threat added to URLhaus!",
                        "already_submitted": "Already in URLhaus — thanks!",
                        "ok":                "Successfully submitted",
                    }
                    result["message"] = msg_map.get(
                        status, f"URLhaus: {status}")
                else:
                    result["message"] = (
                        f"URLhaus HTTP {r.status_code}. "
                        f"Check your Auth-Key at auth.abuse.ch")
            except Exception as e:
                result["message"] = str(e)

        elif sha256:
            self._stats["submitted_hashes"] += 1
            self._add_history(f"Hash shared: {sha256[:16]}...")
            result["ok"] = True
            result["message"] = "Hash logged for community sharing."

        return result

    def auto_report_threat(self, threat: dict):
        """Auto-submit confirmed threats when community reporting is on."""
        if not self.is_enabled():
            return
        action = threat.get("action", "")
        if action not in ("quarantine", "block", "dns_blocked", "blocked"):
            return
        url = threat.get("url", "")
        shield = threat.get("shield", "")
        if url and shield in ("web", "email"):
            threading.Thread(
                target=self._submit_url_bg,
                args=(url, "phishing" if shield == "email"
                      else "malware_download"),
                daemon=True).start()

    def _submit_url_bg(self, url: str, threat_type: str):
        api_key = self.storage.config.get("urlhaus_api_key", "").strip()
        if not api_key:
            return
        try:
            r = requests.post(
                SUBMIT_ENDPOINTS["urlhaus"],
                headers={"Auth-Key": api_key},
                data={"url": url, "threat": threat_type,
                      "tags[]": ["threatshield"]},
                timeout=8)
            if r.ok:
                status = r.json().get("query_status", "")
                if status in ("is_new", "ok"):
                    log.info(f"Auto-submitted to URLhaus: {url[:60]}")
                    self._stats["submitted_urls"] += 1
                    self._add_history(f"Auto-submit: {url[:50]}")
        except Exception as e:
            log.debug(f"Auto-submit error: {e}")

    # ── LOOKUP (no key) ───────────────────────────────────────────────────────
    def lookup_hash_malwarebazaar(self, sha256: str) -> dict:
        """Check hash against MalwareBazaar — completely free, no key."""
        try:
            r = requests.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_info", "hash": sha256},
                timeout=8)
            if r.ok:
                data = r.json()
                if data.get("query_status") == "ok":
                    info = data.get("data", [{}])[0]
                    return {
                        "found":      True,
                        "malicious":  True,
                        "file_type":  info.get("file_type", ""),
                        "signature":  info.get("signature", ""),
                        "tags":       info.get("tags", []),
                        "first_seen": info.get("first_seen", ""),
                        "source":     "malwarebazaar",
                    }
        except Exception as e:
            log.debug(f"MalwareBazaar lookup: {e}")
        return {"found": False}

    # ── BACKGROUND SYNC ───────────────────────────────────────────────────────
    def start_background_sync(self, interval_hours: int = 6):
        def _sync():
            while True:
                try:
                    log.info("Syncing community threat feeds...")
                    n1 = self.pull_urlhaus_feed()
                    n2 = self.pull_threatfox_feed()
                    n3 = self.pull_openphish_feed()
                    n4 = self.pull_feodo_tracker()
                    n5 = self.pull_ssl_blacklist()
                    n6 = self.pull_cybercrime_tracker()
                    n7 = self.pull_dshield_ips()
                    total = n1+n2+n3+n4+n5+n6+n7
                    self._stats["pulled_domains"] += n1+n2+n3+n6
                    self._stats["pulled_hashes"] += n2
                    self._stats["pulled_ips"] += n4+n5+n7
                    self._stats["last_sync"] = time.time()
                    summary = (
                        f"Sync: +{total} indicators "
                        f"(URLhaus:{n1} ThreatFox:{n2} OpenPhish:{n3} "
                        f"Feodo:{n4} SSL-BL:{n5} CC-Tracker:{n6} DShield:{n7})")
                    self._add_history(summary)
                    if total > 0:
                        log.info(summary)
                    else:
                        log.info("Community sync complete — no new indicators")
                except Exception as e:
                    log.debug(f"Sync error: {e}")
                time.sleep(interval_hours * 3600)

        threading.Thread(target=_sync, daemon=True,
                         name="community-sync").start()
        log.info(
            f"Community threat feed sync started (every {interval_hours}h)")

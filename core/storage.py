"""
ThreatShield AI — Storage Engine
Works in both development and bundled EXE.
All data files stored next to the executable.
"""
import json
import time
import sys
from pathlib import Path


def get_base_dir() -> Path:
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).parent
    return Path(__file__).parent.parent


BASE_DIR = get_base_dir()
DATA_DIR = BASE_DIR / "data"


class Storage:
    def __init__(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        (DATA_DIR / "quarantine").mkdir(exist_ok=True)
        (DATA_DIR / "sandbox_reports").mkdir(exist_ok=True)
        (DATA_DIR / "sandbox_extract").mkdir(exist_ok=True)

        self.config           = self._load("config.json",           self._default_config())
        self.learned_patterns = self._load("learned_patterns.json", self._default_patterns())
        self.threat_log       = self._load("threat_log.json",       [])
        self.url_cache        = self._load("url_cache.json",        {})

    def _default_config(self):
        return {
            "active_shields":      ["email", "web", "endpoint"],
            "virustotal_api_key":  "",
            "email_accounts":      [],
            "community_reporting": False,
            "notify_on_threat":    True,
            "auto_quarantine":     False,
        }

    def _default_patterns(self):
        return {
            "safe_senders":     [],
            "safe_domains":     [],
            "phishing_keywords":[],
            "malicious_hashes": [],
            "safe_hashes":      [],
            "blocked_senders":  [],
        }

    def _load(self, filename: str, default):
        path = DATA_DIR / filename
        try:
            if path.exists():
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        # save default
        self.save(filename, default)
        return default

    def save(self, filename: str, data):
        path = DATA_DIR / filename
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            pass

    def log_threat(self, threat: dict):
        threat["timestamp"] = time.time()
        self.threat_log.append(threat)
        self.save("threat_log.json", self.threat_log)

    def update_learned(self, key: str, value: str):
        lst = self.learned_patterns.get(key, [])
        if value not in lst:
            lst.append(value)
            self.learned_patterns[key] = lst
            self.save("learned_patterns.json", self.learned_patterns)

    def cache_url(self, url: str, is_safe: bool):
        self.url_cache[url] = {
            "safe":       is_safe,
            "checked_at": time.time(),
        }
        self.save("url_cache.json", self.url_cache)

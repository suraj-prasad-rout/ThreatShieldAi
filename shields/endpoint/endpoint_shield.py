"""
ThreatShield AI — Endpoint Protection Shield
Industry-grade | Offline-First | Persistent Warnings | USB | Full Coverage

Key behaviors:
- Alert popup is PERSISTENT (cannot be closed with X)
- Monitors file access attempts while popup is shown
- Repeated popup if user tries to open/extract before deciding
- USB drives auto-scanned on insertion
- Full file scan + VirusTotal on every risky file
- Ransomware behavior detection
"""
import os
import hashlib
import shutil
import time
import threading
import re
import math
import struct
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from core.logger import get_logger

log = get_logger("endpoint_shield")

WATCH_DIRS = [
    Path.home() / "Downloads",
    Path.home() / "Desktop",
    Path.home() / "Documents",
    Path.home() / "AppData" / "Local" / "Temp",
]

HIGH_RISK_EXT = {
    ".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".jar", ".com", ".scr", ".pif", ".reg", ".hta", ".wsf",
}
MEDIUM_RISK_EXT = {
    ".dll", ".sys", ".drv", ".ocx",
    ".doc", ".docm", ".xlsm", ".pptm",
}
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".gz", ".tar"}
RANSOMWARE_EXT = {
    ".encrypted", ".locked", ".crypto", ".crypt", ".enc",
    ".locky", ".cerber", ".zepto", ".odin", ".aesir",
    ".osiris", ".zzzzz", ".thor", ".micro", ".surprise",
}

ARCHIVE_PASSWORDS = [b"infected", b"malware",
                     b"virus", b"sample", b"1234", b""]

QUARANTINE_DIR = Path(__file__).parent.parent.parent / "data" / "quarantine"

OFFLINE_SIGNATURES = [
    (r"your files have been encrypted",       50, "Ransomware note"),
    (r"vssadmin.*delete.*shadows",            45, "Shadow copy deletion"),
    (r"bcdedit.*recoveryenabled.*no",         40, "Recovery disabled"),
    (r"bitcoin|btc.*wallet|pay.*ransom",      40, "Ransom payment demand"),
    (r"setwindowshookex",                     40, "Keyboard hook API"),
    (r"getasynckeystate",                     35, "Key state monitoring"),
    (r"createremotethread",                   40, "Process injection"),
    (r"virtualallocex",                       35, "Remote memory alloc"),
    (r"writeprocessmemory",                   35, "Process memory write"),
    (r"software\\microsoft\\windows\\currentversion\\run", 35, "Autorun registry"),
    (r"schtasks.*create",                     30, "Scheduled task"),
    (r"isdebuggerpresent",                    30, "Anti-debug"),
    (r"vmware|virtualbox|vbox|sandboxie",     25, "VM detection"),
    (r"chrome.*logindata|firefox.*key4",      30, "Browser credential access"),
    (r"getclipboarddata|clipboarddata",       20, "Clipboard access"),
    (r"urldownloadtofile|internetopenurl",    30, "Remote file download"),
    (r"powershell.*-enc|-encodedcommand",     25, "Encoded PS command"),
    (r"\.onion\b",                            35, "Tor C2"),
    (r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", 20, "IP-based URL"),
    (r"/bin/busybox|/bin/sh\x00",            40, "IoT botnet (Mirai)"),
    (r"scanner|telnet.*login|brute.*force",   30, "Network scanner"),
]


def _offline_score(data: bytes) -> tuple:
    indicators = []
    score = 0
    entropy = _entropy(data)
    if entropy > 7.8:
        indicators.append(f"Entropy {entropy:.2f} — heavily packed/encrypted")
        score += 30
    elif entropy > 7.2:
        indicators.append(f"Entropy {entropy:.2f} — possibly packed")
        score += 15
    if len(data) >= 4 and data[:4] == b"\x7fELF":
        indicators.append("ELF binary — Linux/IoT malware")
        score += 20
    try:
        text = data.decode("latin-1", errors="ignore").lower()
        for pattern, sig_score, desc in OFFLINE_SIGNATURES:
            if re.search(pattern, text, re.IGNORECASE):
                indicators.append(f"Signature: {desc}")
                score += sig_score
                if score >= 100:
                    break
    except Exception:
        pass
    try:
        ips = re.findall(
            r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b',
            data.decode("latin-1", errors="ignore"))
        pub = [ip for ip in set(ips)
               if not ip.startswith(("192.168.", "10.", "172.1", "127.", "0."))]
        if len(pub) > 3:
            indicators.append(f"Hardcoded IPs: {', '.join(pub[:3])}")
            score += min(len(pub)*5, 25)
    except Exception:
        pass
    return min(score, 100), indicators


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0]*256
    for b in data:
        freq[b] += 1
    e = 0.0
    n = len(data)
    for f in freq:
        if f > 0:
            p = f/n
            e -= p*math.log2(p)
    return e


def _is_internet() -> bool:
    try:
        import socket
        socket.setdefaulttimeout(2)
        socket.create_connection(("8.8.8.8", 53))
        return True
    except Exception:
        return False


class EndpointShield:
    def __init__(self, storage, bus):
        self.storage = storage
        self.bus = bus
        self.observer = Observer()
        self._mod_tracker = {}
        self._mod_lock = threading.Lock()
        self._scan_pool = ThreadPoolExecutor(
            max_workers=2, thread_name_prefix="ep-scan")
        self._usb_known = set()
        # track files with active alerts (prevent double-alert)
        self._active_alerts = set()
        self._alert_lock = threading.Lock()

    def start(self):
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        handler = _FileHandler(self.storage, self.bus, self)
        for d in WATCH_DIRS:
            if d.exists():
                self.observer.schedule(handler, str(d), recursive=True)
                log.info(f"Watching: {d}")
        self.observer.start()
        threading.Thread(target=self._ransomware_monitor,
                         daemon=True, name="ransomware-mon").start()
        threading.Thread(target=self._process_monitor,
                         daemon=True, name="process-mon").start()
        threading.Thread(target=self._usb_monitor,
                         daemon=True, name="usb-mon").start()
        log.info("Endpoint shield active — full coverage mode "
                 "(recursive + full scan + 30s process monitor)")
        self.observer.join()

    def submit_scan(self, fn, *args):
        try:
            self._scan_pool.submit(fn, *args)
        except Exception as e:
            log.debug(f"Scan pool error: {e}")

    def track_modification(self, path: str):
        with self._mod_lock:
            now = time.time()
            if path not in self._mod_tracker:
                self._mod_tracker[path] = []
            self._mod_tracker[path].append(now)
            cutoff = now - 30
            self._mod_tracker[path] = [
                t for t in self._mod_tracker[path] if t > cutoff]
            if len(self._mod_tracker) > 1000:
                oldest = sorted(
                    self._mod_tracker,
                    key=lambda k: max(self._mod_tracker[k], default=0))[:100]
                for k in oldest:
                    del self._mod_tracker[k]

    def is_active_alert(self, path: str) -> bool:
        with self._alert_lock:
            return str(path) in self._active_alerts

    def set_active_alert(self, path: str, active: bool):
        with self._alert_lock:
            if active:
                self._active_alerts.add(str(path))
            else:
                self._active_alerts.discard(str(path))

    # Paths that generate many temp file changes legitimately
    _SAFE_TEMP_PATTERNS = [
        "appx", ".tmp", "microsoftedge", "windowsapps",
        "crashdumps", "diagnostics", "package cache",
    ]

    def _is_safe_temp_path(self, path: str) -> bool:
        pl = path.lower()
        return any(p in pl for p in self._SAFE_TEMP_PATTERNS)

    def _ransomware_monitor(self):
        while True:
            try:
                time.sleep(5)
                with self._mod_lock:
                    now = time.time()
                    # only count files modified in last 10s
                    # exclude known Windows system temp patterns
                    recently = [
                        p for p, times in self._mod_tracker.items()
                        if any(now-t < 10 for t in times)
                        and not self._is_safe_temp_path(p)
                    ]
                # raised threshold: 25 unique non-system files in 10s
                if len(recently) >= 25:
                    log.warning(
                        f"RANSOMWARE: {len(recently)} files modified in 10s!")
                    self._ransomware_alert(recently)
            except Exception as e:
                log.debug(f"Ransomware monitor error: {e}")

    def _ransomware_alert(self, affected):
        try:
            from shields.endpoint.endpoint_alert import show_ransomware_alert
            show_ransomware_alert(affected[:10], self.storage, self.bus)
        except Exception as e:
            log.error(f"Ransomware alert: {e}")
        self.storage.log_threat({
            "shield": "endpoint", "type": "ransomware_behavior",
            "files":  [str(f) for f in affected[:10]],
            "count":  len(affected),
        })
        self.bus.emit("threat_found", {
            "shield": "endpoint",
            "file":   f"{len(affected)} files being encrypted",
        })

    def _process_monitor(self):
        try:
            import psutil
        except ImportError:
            return
        SUSPICIOUS = {"keylogger", "ratclient",
                      "njrat", "darkcomet", "stealer"}
        known_pids = set()
        while True:
            try:
                time.sleep(30)
                for proc in psutil.process_iter(["pid", "name", "exe"]):
                    try:
                        pid = proc.info["pid"]
                        name = (proc.info["name"] or "").lower()
                        exe = (proc.info["exe"] or "").lower()
                        if pid in known_pids:
                            continue
                        for ind in SUSPICIOUS:
                            if ind in name or ind in exe:
                                known_pids.add(pid)
                                log.warning(
                                    f"Suspicious process: {name} PID {pid}")
                                self.storage.log_threat({
                                    "shield": "endpoint",
                                    "type":   "suspicious_process",
                                    "name":   name, "pid": pid,
                                })
                                self.bus.emit("threat_found", {
                                    "shield": "endpoint",
                                    "file":   f"Suspicious process: {name}",
                                })
                                break
                    except Exception:
                        pass
                if len(known_pids) > 500:
                    known_pids = set(list(known_pids)[-200:])
            except Exception as e:
                log.debug(f"Process monitor error: {e}")

    def _usb_monitor(self):
        import string
        try:
            import win32api
            import win32file
            HAS_WIN32 = True
        except ImportError:
            HAS_WIN32 = False

        def _get_removable():
            drives = set()
            if HAS_WIN32:
                try:
                    for d in win32api.GetLogicalDriveStrings().split("\x00"):
                        if d and win32file.GetDriveType(d) == win32file.DRIVE_REMOVABLE:
                            drives.add(d)
                except Exception:
                    pass
            else:
                for letter in string.ascii_uppercase[2:]:
                    drive = f"{letter}:\\"
                    if os.path.exists(drive):
                        try:
                            if shutil.disk_usage(drive).total < 256*1024*1024*1024:
                                drives.add(drive)
                        except Exception:
                            pass
            return drives

        log.info("USB monitor active")
        while True:
            try:
                time.sleep(10)
                current = _get_removable()
                for drive in current - self._usb_known:
                    log.info(f"USB detected: {drive}")
                    self.submit_scan(self._scan_usb, drive)
                self._usb_known = current
            except Exception as e:
                log.debug(f"USB monitor error: {e}")

    def _scan_usb(self, drive: str):
        log.info(f"Scanning USB: {drive}")
        found = scanned = 0
        try:
            for root_dir, dirs, files in os.walk(drive):
                dirs[:] = [d for d in dirs if d.lower() not in {
                    "system volume information", "$recycle.bin", "windows"}]
                for fname in files:
                    ext = Path(fname).suffix.lower()
                    if ext not in HIGH_RISK_EXT | MEDIUM_RISK_EXT | ARCHIVE_EXT:
                        continue
                    fpath = Path(root_dir)/fname
                    scanned += 1
                    try:
                        sha256 = self._hash(fpath)
                        known = self.storage.learned_patterns.get(
                            "malicious_hashes", [])
                        if sha256 in known:
                            self._alert_usb(fpath, sha256,
                                            "Known malicious file")
                            found += 1
                            continue
                        with open(fpath, "rb") as f:
                            data = f.read()
                        score, indicators = _offline_score(data)
                        if score >= 40:
                            self._alert_usb(
                                fpath, sha256,
                                f"Suspicious (score {score}): "
                                f"{indicators[0] if indicators else ''}",
                                indicators)
                            found += 1
                        elif ext in HIGH_RISK_EXT and _is_internet():
                            vt = self._vt_check(sha256)
                            if vt["malicious"]:
                                self._alert_usb(
                                    fpath, sha256,
                                    f"VT: {vt['detections']} vendors flagged")
                                found += 1
                    except Exception as e:
                        log.debug(f"USB file error {fname}: {e}")
        except Exception as e:
            log.debug(f"USB scan error: {e}")
        log.info(f"USB done: {drive} — {scanned} files, {found} threat(s)")

    def _alert_usb(self, path, sha256, reason, indicators=None):
        try:
            from shields.endpoint.endpoint_alert import show_file_alert
            show_file_alert(
                path=path, sha256=sha256, source="usb_scan",
                reason=reason, risk_level="high", vt_result=None,
                storage=self.storage, bus=self.bus,
                on_quarantine=lambda: self._quarantine(
                    path, "usb_scan", {"sha256": sha256}),
                on_sandbox=lambda: threading.Thread(
                    target=self._sandbox,
                    args=(path,), daemon=True).start(),
                on_allow=lambda: self._allow(path, sha256),
            )
        except Exception as e:
            log.error(f"USB alert error: {e}")
        self.storage.log_threat({
            "shield": "endpoint", "type": "usb_threat",
            "file":   path.name, "sha256": sha256, "reason": reason,
        })
        self.bus.emit("threat_found", {
            "shield": "endpoint", "file": f"USB: {path.name}",
        })

    def _quarantine(self, path, source, meta=None):
        try:
            if not path.exists():
                return
            dest = QUARANTINE_DIR / f"{int(time.time())}_{path.name}"
            shutil.move(str(path), str(dest))
            sha256 = (meta or {}).get("sha256", "")
            if sha256:
                self.storage.update_learned("malicious_hashes", sha256)
            log.warning(f"Quarantined: {path.name}")
        except Exception as e:
            log.error(f"Quarantine failed: {e}")

    def _sandbox(self, path):
        try:
            from shields.endpoint.sandbox import run_sandbox
            run_sandbox(path, self.storage, self.bus)
        except Exception as e:
            log.error(f"Sandbox error: {e}")

    def _allow(self, path, sha256):
        self.storage.update_learned("safe_hashes", sha256)
        log.info(f"Allowed: {path.name}")

    def _hash(self, path) -> str:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

    def _vt_check(self, sha256) -> dict:
        import requests
        api_key = self.storage.config.get("virustotal_api_key", "")
        if not api_key:
            return {"malicious": False, "detections": 0, "source": "no_key"}
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers={"x-apikey": api_key}, timeout=8)
            if r.status_code == 200:
                stats = r.json()["data"]["attributes"]["last_analysis_stats"]
                mal = stats.get("malicious", 0)
                sus = stats.get("suspicious", 0)
                return {"malicious": (mal+sus) > 0, "detections": mal+sus,
                        "stats": stats, "source": "virustotal"}
            elif r.status_code == 404:
                return {"malicious": False, "detections": 0, "source": "unknown"}
        except Exception as e:
            log.debug(f"VT error: {e}")
        return {"malicious": False, "detections": 0, "source": "error"}


class _FileHandler(FileSystemEventHandler):
    def __init__(self, storage, bus, shield):
        self.storage = storage
        self.bus = bus
        self.shield = shield
        self._seen = set()
        self._seen_lock = threading.Lock()

    def on_created(self, event):
        if event.is_directory:
            return
        path = Path(event.src_path)
        key = str(path)
        with self._seen_lock:
            if key in self._seen:
                return
            self._seen.add(key)
            if len(self._seen) > 500:
                self._seen = set(list(self._seen)[-200:])
        self.shield.submit_scan(self._check_file, path)

    def on_modified(self, event):
        if event.is_directory:
            return
        path = Path(event.src_path)
        self.shield.track_modification(str(path))
        if path.suffix.lower() in RANSOMWARE_EXT:
            log.warning(f"Ransomware extension: {path.name}")
            self.shield._quarantine(path, "ransomware_ext", {})

    def on_moved(self, event):
        if event.is_directory:
            return
        dest = Path(event.dest_path)
        if dest.suffix.lower() in RANSOMWARE_EXT:
            log.warning(f"Renamed to ransomware ext: {dest.name}")
            self.shield._quarantine(dest, "ransomware_rename", {})

    def _check_file(self, path: Path):
        try:
            self._wait_stable(path)
            if not path.exists():
                return

            # skip files in sandbox_extract — these are our own temp files
            path_str = str(path).lower()
            if "sandbox_extract" in path_str or "sandbox_reports" in path_str:
                log.debug(f"Skipping sandbox temp file: {path.name}")
                return

            ext = path.suffix.lower()
            sha256 = self.shield._hash(path)

            if sha256:
                safe = self.storage.learned_patterns.get("safe_hashes", [])
                if sha256 in safe:
                    return

                known = self.storage.learned_patterns.get(
                    "malicious_hashes", [])
                if sha256 in known:
                    log.warning(f"Known malicious: {path.name}")
                    self._alert(path, sha256, "known_hash",
                                "Previously confirmed malicious file",
                                "high")
                    return

            if ext in ARCHIVE_EXT:
                self._scan_archive(path, sha256)
            elif ext in HIGH_RISK_EXT:
                self._scan_file(path, sha256, "high")
            elif ext in MEDIUM_RISK_EXT:
                self._scan_file(path, sha256, "medium")

        except Exception as e:
            log.debug(f"Check error {path}: {e}")

    def _wait_stable(self, path: Path, timeout: int = 30):
        prev = -1
        still = 0
        t0 = time.time()
        while time.time()-t0 < timeout:
            try:
                sz = path.stat().st_size if path.exists() else 0
                if sz == prev:
                    still += 1
                    if still >= 2:
                        return
                else:
                    still = 0
                prev = sz
            except Exception:
                pass
            time.sleep(1)

    def _scan_file(self, path: Path, sha256: str, risk_level: str):
        try:
            with open(path, "rb") as f:
                data = f.read()
        except Exception:
            return

        score, indicators = _offline_score(data)
        if score >= 50:
            log.warning(f"Offline: {path.name} score={score}")
            self._alert(path, sha256, "offline_heuristic",
                        f"Score {score}/100: "
                        f"{indicators[0] if indicators else 'suspicious'}",
                        risk_level)
            return

        # VT check
        vt = self.shield._vt_check(sha256)
        if vt["malicious"]:
            log.warning(f"VT: {path.name} ({vt['detections']} detections)")
            self._alert(path, sha256, "virustotal",
                        f"Flagged by {vt['detections']} security vendors",
                        risk_level, vt)
        else:
            log.info(f"Clean: {path.name} [offline={score} vt={vt['source']}]")

    def _scan_archive(self, archive_path: Path, archive_sha: str):
        try:
            import pyzipper
            with pyzipper.AESZipFile(str(archive_path), 'r') as zf:
                names = zf.namelist()
                log.info(
                    f"Archive: {archive_path.name} — {len(names)} file(s)")
                for name in names:
                    ext = Path(name).suffix.lower()
                    data = None
                    for pwd in ARCHIVE_PASSWORDS:
                        try:
                            data = zf.read(
                                name, pwd=pwd) if pwd else zf.read(name)
                            if data:
                                break
                        except Exception:
                            continue
                    if not data:
                        continue

                    sha256 = hashlib.sha256(data).hexdigest()
                    known = self.storage.learned_patterns.get(
                        "malicious_hashes", [])
                    if sha256 in known:
                        self._alert(archive_path, sha256, "known_hash",
                                    f"Archive contains known malware: {name}",
                                    "high")
                        return

                    score, indicators = _offline_score(data)
                    if score >= 50:
                        self._alert(archive_path, sha256, "offline_heuristic",
                                    f"Archive: suspicious file {name} (score {score})",
                                    "high")
                        return

                    if ext in HIGH_RISK_EXT | MEDIUM_RISK_EXT:
                        vt = self.shield._vt_check(sha256)
                        if vt["malicious"]:
                            self.storage.update_learned(
                                "malicious_hashes", sha256)
                            self._alert(archive_path, sha256, "virustotal",
                                        f"Archive malware: {name} — "
                                        f"{vt['detections']} vendors flagged",
                                        "high", vt)
                            return
        except ImportError:
            log.warning("pyzipper not installed")
        except Exception as e:
            log.debug(f"Archive scan error: {e}")

    def _alert(self, path, sha256, source, reason,
               risk_level, vt_result=None):
        # prevent duplicate alerts for same file
        if self.shield.is_active_alert(str(path)):
            return
        self.shield.set_active_alert(str(path), True)

        try:
            from shields.endpoint.endpoint_alert import show_file_alert
            show_file_alert(
                path=path, sha256=sha256, source=source,
                reason=reason, risk_level=risk_level,
                vt_result=vt_result, storage=self.storage,
                bus=self.bus,
                on_quarantine=lambda: self.shield._quarantine(
                    path, source, {"sha256": sha256}),
                on_sandbox=lambda: threading.Thread(
                    target=self.shield._sandbox,
                    args=(path,), daemon=True).start(),
                on_allow=lambda: self.shield._allow(path, sha256),
            )
        except Exception as e:
            log.error(f"Alert error: {e}")
            self.shield._quarantine(path, source, {"sha256": sha256})
        finally:
            self.shield.set_active_alert(str(path), False)

        self.storage.log_threat({
            "shield": "endpoint", "type": "file_threat",
            "file":   path.name, "sha256": sha256,
            "source": source, "reason": reason,
            "score":  0.8 if risk_level == "high" else 0.5,
        })
        self.bus.emit("threat_found", {
            "shield": "endpoint", "file": path.name,
        })

"""
ThreatShield AI — Behavioral Sandbox v2.0
Key fix: analyze bytes IN MEMORY — no disk read/write cycle for analysis.
Only write to disk if dynamic execution is needed (x64 PE only).
"""
import os
import re
import json
import math
import time
import struct
import hashlib
import subprocess
import shutil
import tempfile
from pathlib import Path
from core.logger import get_logger

log = get_logger("sandbox")

SANDBOX_DIR = Path(__file__).parent.parent.parent / "data" / "sandbox_reports"
SANDBOX_EXTRACT = Path(__file__).parent.parent.parent / \
    "data" / "sandbox_extract"
SANDBOX_TIMEOUT = 30

ARCHIVE_PASSWORDS = [
    b"infected", b"malware", b"virus", b"sample",
    b"1234", b"password", b"test", b"",
]

MALWARE_SIGNATURES = [
    (r"your files have been encrypted",       50, "Ransomware: ransom note"),
    (r"bitcoin|btc.*wallet|pay.*ransom",       40, "Ransomware: payment demand"),
    (r"vssadmin.*delete.*shadows",             45,
     "Ransomware: shadow copy deletion"),
    (r"setwindowshookex",                      40, "Keylogger: keyboard hook"),
    (r"getasynckeystate",                      35, "Keylogger: key state API"),
    (r"createremotethread",                    40, "Trojan: process injection"),
    (r"virtualallocex",                        35, "Trojan: remote memory"),
    (r"writeprocessmemory",                    35, "Trojan: memory write"),
    (r"software\\microsoft\\windows\\currentversion\\run", 35, "Persistence: autorun"),
    (r"schtasks.*create",                      30, "Persistence: scheduled task"),
    (r"isdebuggerpresent",                     30, "Evasion: anti-debug"),
    (r"vmware|virtualbox|vbox|sandboxie",      25, "Evasion: VM detection"),
    (r"chrome.*logindata|firefox.*key4",       30, "Stealer: browser creds"),
    (r"urldownloadtofile|internetopenurl",     30, "Dropper: file download"),
    (r"powershell.*-enc|-encodedcommand",      25, "Dropper: encoded PS"),
    (r"\.onion\b",                             35, "C2: Tor"),
    (r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", 20, "C2: IP URL"),
    (r"/bin/busybox|/bin/sh\x00",             40, "Botnet: IoT/Mirai"),
]


def run_sandbox(path: Path, storage, bus):
    SANDBOX_DIR.mkdir(parents=True, exist_ok=True)
    SANDBOX_EXTRACT.mkdir(parents=True, exist_ok=True)
    ext = path.suffix.lower()
    if ext in {".zip", ".rar", ".7z", ".gz", ".tar"}:
        _sandbox_archive(path, storage, bus)
    else:
        # for direct files, read bytes then analyze
        try:
            with open(str(path), "rb") as f:
                data = f.read()
            _analyze_bytes(data, path.name, path, storage, bus)
        except Exception as e:
            log.error(f"Cannot read {path.name}: {e}")


def _sandbox_archive(archive_path: Path, storage, bus):
    log.info(f"Extracting archive: {archive_path.name}")

    try:
        import pyzipper
    except ImportError:
        log.error("pyzipper not installed — pip install pyzipper")
        return

    # Read ALL bytes into memory FIRST, close pyzipper completely
    # then analyze from memory — NO disk read-write cycle
    files_in_memory = []
    try:
        with pyzipper.AESZipFile(str(archive_path), 'r') as zf:
            for name in zf.namelist():
                data = None
                for pwd in ARCHIVE_PASSWORDS:
                    try:
                        data = zf.read(name, pwd=pwd) if pwd else zf.read(name)
                        if data:
                            break
                    except Exception:
                        continue
                if data:
                    # copy to new bytes obj
                    files_in_memory.append((name, bytes(data)))
                    log.info(
                        f"Extracted: {Path(name).name} ({len(data):,} bytes)")
                else:
                    log.debug(f"Cannot extract: {name}")
        # pyzipper FULLY closed here
    except Exception as e:
        log.error(f"Archive error: {e}")
        return

    if not files_in_memory:
        log.warning("No files extracted")
        return

    # Analyze each file's bytes directly — no disk read needed
    for name, data in files_in_memory:
        _analyze_bytes(data, name, archive_path, storage, bus,
                       display_name=archive_path.name)


def _analyze_bytes(data: bytes, internal_name: str, source_path: Path,
                   storage, bus, display_name: str = None):
    """
    Analyze file bytes directly in memory.
    Only writes to disk if dynamic execution is needed (x64 PE only).
    """
    name = display_name or internal_name
    log.info(f"Starting analysis: {name}")

    report = {
        "file": name, "timestamp": time.time(),
        "file_type": "unknown", "architecture": "unknown",
        "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
        "entropy": 0.0, "strings_extracted": [],
        "suspicious_urls": [], "suspicious_ips": [], "imports": [],
        "matched_signatures": [], "network_conns": [], "child_procs": [],
        "verdict": "clean", "risk_score": 0,
        "indicators": [], "ai_analysis": "",
    }

    log.info(f"Analyzing {len(data):,} bytes in memory")

    # format detection
    fmt, arch = _detect_format(data)
    report["file_type"] = fmt
    report["architecture"] = arch
    log.info(f"Format: {fmt}/{arch}")

    # entropy
    entropy = _entropy(data)
    report["entropy"] = round(entropy, 3)
    if entropy > 7.8:
        report["indicators"].append(
            f"Entropy {entropy:.2f} — heavily packed/encrypted")
        report["risk_score"] += 30
    elif entropy > 7.2:
        report["indicators"].append(
            f"Entropy {entropy:.2f} — possibly packed")
        report["risk_score"] += 20

    # strings + signatures
    strings = _extract_strings(data)
    report["strings_extracted"] = strings[:50]
    combined = (" ".join(strings) +
                data.decode("latin-1", errors="ignore")).lower()

    for pattern, score, desc in MALWARE_SIGNATURES:
        if re.search(pattern, combined, re.IGNORECASE):
            report["matched_signatures"].append(desc)
            report["indicators"].append(f"Signature: {desc}")
            report["risk_score"] += score

    # suspicious URLs
    for url in set(re.findall(
            r'https?://[^\s\x00-\x1f\x7f-\xff"\'<>]{8,100}',
            combined)[:20]):
        if re.search(
                r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\.onion\b',
                url, re.IGNORECASE):
            report["suspicious_urls"].append(url)
            report["indicators"].append(f"Suspicious URL: {url[:80]}")
            report["risk_score"] += 20

    # hardcoded IPs
    pub_ips = [
        ip for ip in set(re.findall(
            r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', combined))
        if not ip.startswith(("192.168.", "10.", "172.", "127.", "0."))
    ]
    if pub_ips:
        report["suspicious_ips"] = pub_ips[:10]
        report["indicators"].append(
            f"Hardcoded IPs: {', '.join(pub_ips[:5])}")
        report["risk_score"] += min(len(pub_ips) * 10, 30)

    # PE imports
    if fmt == "PE":
        imports = _parse_pe_imports(data)
        report["imports"] = imports
        _analyze_imports(imports, report)

    # AI summary
    report["ai_analysis"] = _ai_summary(report)

    # dynamic execution — x64 PE only, write to disk just for this
    if fmt == "PE" and arch == "x64":
        _dynamic_from_bytes(data, internal_name, report)
    elif fmt == "PE" and arch == "x86":
        msg = ("x86 PE — dynamic execution skipped "
               "(requires .NET/VC++ which causes system dialogs). "
               "Static analysis complete.")
        log.info(msg)
        report["indicators"].append(msg)
    else:
        msg = f"Static analysis only — {fmt}/{arch}"
        log.info(msg)
        report["indicators"].append(msg)

    # finalize verdict
    score = min(report["risk_score"], 100)
    report["risk_score"] = score
    report["verdict"] = (
        "malicious" if score >= 60 else
        "suspicious" if score >= 25 else "clean")

    log.info(
        f"Analysis complete: {name} — "
        f"verdict={report['verdict']} score={score}/100 "
        f"sigs={len(report['matched_signatures'])}")

    _save_and_show(report, source_path, storage, bus)


def _dynamic_from_bytes(data: bytes, name: str, report: dict):
    """Write bytes to temp file for dynamic execution (x64 only)."""
    ext = Path(name).suffix.lower()
    if ext not in (".exe", ".bat", ".ps1"):
        return

    tmp_path = None
    try:
        # Write to sandbox_extract — not in watched dirs
        SANDBOX_EXTRACT.mkdir(parents=True, exist_ok=True)
        tmp_path = SANDBOX_EXTRACT / f"dyn_{int(time.time())}{ext}"
        tmp_path.write_bytes(data)

        cmd = {
            ".exe": [str(tmp_path)],
            ".bat": ["cmd.exe", "/c", str(tmp_path)],
            ".ps1": ["powershell.exe", "-ExecutionPolicy",
                     "Bypass", "-File", str(tmp_path)],
        }.get(ext)

        if not cmd:
            return

        import ctypes
        old_mode = ctypes.windll.kernel32.SetErrorMode(0x8007)

        si = subprocess.STARTUPINFO()
        si.dwFlags = subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            startupinfo=si,
            creationflags=(
                subprocess.CREATE_NEW_PROCESS_GROUP |
                0x08000000 |  # CREATE_NO_WINDOW
                0x00004000),  # BELOW_NORMAL_PRIORITY
            close_fds=True)

        ctypes.windll.kernel32.SetErrorMode(old_mode)
        log.info(f"Dynamic: PID {proc.pid} — {SANDBOX_TIMEOUT}s")

        try:
            import psutil
            sp = psutil.Process(proc.pid)
            start = time.time()
            while time.time() - start < SANDBOX_TIMEOUT:
                try:
                    if not sp.is_running():
                        break
                    for child in sp.children(recursive=True):
                        try:
                            cn = child.name()
                            if cn not in report["child_procs"]:
                                report["child_procs"].append(cn)
                                if cn.lower() in {
                                        "cmd.exe", "powershell.exe",
                                        "wscript.exe"}:
                                    report["indicators"].append(
                                        f"Spawned: {cn}")
                                    report["risk_score"] += 20
                        except Exception:
                            pass
                    try:
                        for conn in sp.connections(kind="inet"):
                            if conn.status == "ESTABLISHED" and conn.raddr:
                                addr = f"{conn.raddr.ip}:{conn.raddr.port}"
                                if addr not in report["network_conns"]:
                                    report["network_conns"].append(addr)
                                    report["indicators"].append(
                                        f"C2 connection: {addr}")
                                    report["risk_score"] += 30
                    except Exception:
                        pass
                    time.sleep(2)
                except Exception:
                    break
        except ImportError:
            pass
        finally:
            try:
                proc.kill()
                proc.wait(timeout=3)
            except Exception:
                pass

    except Exception as e:
        log.info(f"Dynamic execution error: {e}")
        report["indicators"].append(f"Dynamic: {e}")
    finally:
        if tmp_path and tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception:
                pass


def _detect_format(data):
    if len(data) < 4:
        return "unknown", "unknown"
    if data[:2] == b"MZ":
        if len(data) > 64:
            off = struct.unpack_from("<I", data, 60)[0]
            if off + 6 < len(data) and data[off:off+4] == b"PE\x00\x00":
                m = struct.unpack_from("<H", data, off+4)[0]
                arch = {0x014c: "x86", 0x8664: "x64",
                        0x01c4: "ARM", 0xaa64: "ARM64"}.get(m, "unknown")
                return "PE", arch
        return "PE", "unknown"
    if data[:4] == b"\x7fELF":
        return "ELF", ("x64" if data[4] == 2 else "x86")
    if data[:4] == b"PK\x03\x04":
        return "ZIP", "archive"
    if data[:4] == b"%PDF":
        return "PDF", "document"
    try:
        t = data[:200].decode("utf-8", errors="strict").lower()
        if t.startswith("#!"):
            return "Script", "shell"
        if "powershell" in t:
            return "Script", "PowerShell"
    except Exception:
        pass
    return "binary", "unknown"


def _entropy(data):
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    e = 0.0
    n = len(data)
    for f in freq:
        if f > 0:
            p = f / n
            e -= p * math.log2(p)
    return e


def _extract_strings(data, min_len=6):
    strings = []
    for m in re.compile(
            b"[\x20-\x7e]{" + str(min_len).encode() + b","
            b"}").finditer(data):
        s = m.group().decode("ascii", errors="ignore").strip()
        if s:
            strings.append(s)
    return list(set(strings))


def _parse_pe_imports(data):
    imports = []
    try:
        pat = re.compile(
            b"(Create(?:Process|Thread|RemoteThread|File|Mutex)|"
            b"Virtual(?:Alloc|Protect|AllocEx)|WriteProcessMemory|"
            b"GetAsyncKeyState|SetWindowsHookEx|URLDownloadToFile|"
            b"RegSetValue|InternetOpen|WinExec|ShellExecute)"
            b"(?:A|W|Ex)?\x00", re.IGNORECASE)
        for m in pat.finditer(data):
            api = m.group().rstrip(b"\x00").decode("ascii", errors="ignore")
            if api not in imports:
                imports.append(api)
    except Exception:
        pass
    return imports


def _analyze_imports(imports, report):
    DANGEROUS = {
        "CreateRemoteThread": (40, "Process injection"),
        "VirtualAllocEx":     (35, "Remote memory allocation"),
        "WriteProcessMemory": (35, "Process memory manipulation"),
        "SetWindowsHookEx":   (40, "Keyboard hook — keylogger"),
        "GetAsyncKeyState":   (35, "Key state monitoring"),
        "URLDownloadToFile":  (30, "Remote file download"),
        "RegSetValue":        (20, "Registry modification"),
        "WinExec":            (25, "Command execution"),
        "ShellExecute":       (20, "Shell execution"),
    }
    for imp in imports:
        for api, (score, desc) in DANGEROUS.items():
            if api.lower() in imp.lower():
                report["indicators"].append(f"Import: {imp} — {desc}")
                report["risk_score"] += score
                break


def _ai_summary(report):
    score = report["risk_score"]
    sigs = report["matched_signatures"]
    fmt = report["file_type"]
    lines = []
    if fmt == "ELF":
        lines.append(
            "ELF binary (Linux/IoT malware) — "
            "static analysis only, cannot execute on Windows.")
    elif fmt == "PE":
        lines.append("Windows PE executable — full analysis performed.")
    elif fmt == "Script":
        lines.append("Script file — analyzed for malicious commands.")
    else:
        lines.append(f"{fmt} file — static analysis performed.")
    if report["entropy"] > 7.8:
        lines.append(
            "EXTREMELY high entropy — heavily packed/encrypted, "
            "strong malware evasion indicator.")
    elif report["entropy"] > 7.2:
        lines.append("High entropy — possibly packed or obfuscated.")
    if any("Ransomware" in s for s in sigs):
        lines.append(
            "RANSOMWARE patterns — file encryption and ransom demand behavior.")
    if any("Keylogger" in s for s in sigs):
        lines.append(
            "KEYLOGGER patterns — hooks keyboard to steal credentials.")
    if any("Trojan" in s for s in sigs):
        lines.append(
            "TROJAN/RAT patterns — injects code into other processes.")
    if any("Persistence" in s for s in sigs):
        lines.append(
            "PERSISTENCE — modifies registry or scheduled tasks.")
    if any("Stealer" in s for s in sigs):
        lines.append(
            "DATA STEALER — accesses browser credentials or clipboard.")
    if any("Dropper" in s for s in sigs):
        lines.append(
            "DROPPER — downloads and executes additional payloads.")
    if any("Evasion" in s for s in sigs):
        lines.append(
            "ANTI-ANALYSIS — detects VMs or debuggers.")
    if report["suspicious_ips"]:
        lines.append(
            f"Hardcoded C2 IPs: {', '.join(report['suspicious_ips'][:3])}")
    if report["suspicious_urls"]:
        lines.append("Suspicious embedded URLs — C2 or payload download.")
    if score >= 60:
        lines.append(
            f"VERDICT: MALICIOUS (score {score}/100) — "
            f"Immediate quarantine strongly recommended.")
    elif score >= 25:
        lines.append(
            f"VERDICT: SUSPICIOUS (score {score}/100) — "
            f"Exercise caution before allowing.")
    else:
        lines.append(
            f"VERDICT: CLEAN (score {score}/100) — "
            f"No significant threats detected.")
    return "\n".join(lines)


def _save_and_show(report, source_path, storage, bus):
    try:
        rp = SANDBOX_DIR / f"{int(time.time())}_report.json"
        with open(str(rp), "w") as f:
            json.dump(report, f, indent=2)
        log.info(f"Report saved: {rp.name}")
    except Exception as e:
        log.error(f"Report save: {e}")

    if report["verdict"] in ("malicious", "suspicious"):
        storage.log_threat({
            "shield":      "endpoint",
            "type":        "sandbox",
            "file":        report["file"],
            "verdict":     report["verdict"],
            "score":       report["risk_score"] / 100,
            "action":      "sandboxed",
            "indicators":  report["indicators"][:10],
            "ai_analysis": report["ai_analysis"],
        })
        bus.emit("threat_found", {
            "shield":  "endpoint",
            "file":    report["file"],
            "verdict": report["verdict"],
        })

    try:
        _show_result(report, source_path, storage)
    except Exception as e:
        log.error(f"Result window: {e}")


def _show_result(report, path, storage):
    import tkinter as tk

    verdict = report["verdict"]
    score = report["risk_score"]
    inds = report["indicators"]
    ai = report.get("ai_analysis", "")
    fmt = report["file_type"]
    arch = report["architecture"]

    BG = "#0f1512"
    BG2 = "#141c19"
    BG3 = "#0a0e0d"
    RED = "#e8503a"
    AMBER = "#f0a500"
    TEAL2 = "#25c791"
    BLUE = "#5b9de8"
    TEXT = "#c8ddd8"
    TEXT2 = "#7a9e98"
    TEXT3 = "#5a7a74"

    color = (RED if verdict == "malicious" else
             AMBER if verdict == "suspicious" else TEAL2)

    root = tk.Tk()
    root.title(f"ThreatShield AI — Sandbox: {verdict.upper()}")
    root.configure(bg=BG)
    root.attributes("-topmost", True)
    root.resizable(True, True)

    # Use pack with a fixed-height button bar at bottom
    # so buttons are ALWAYS visible regardless of content height
    root.geometry("660x680")
    root.minsize(600, 500)

    # ── TOP: scrollable content area ──────────────────────────────────────
    # Button bar pinned to bottom FIRST so it's always visible
    # (pack order: bottom frame first, then fill remaining space)

    # BUTTON BAR — packed first so it stays at bottom always
    tk.Frame(root, bg="#1a2e28", height=1).pack(side="bottom", fill="x")
    btn_f = tk.Frame(root, bg=BG2, padx=16, pady=14)
    btn_f.pack(side="bottom", fill="x")

    result = [None]
    def _do(a): result[0] = a; root.destroy()

    bs = {"font": ("Segoe UI", 10, "bold"), "relief": "flat",
          "padx": 12, "pady": 9, "cursor": "hand2", "bd": 0}

    tk.Button(btn_f, text="🔒  Quarantine",
              bg="#1a0808", fg=RED, activebackground="#2a0a0a",
              command=lambda: _do("quarantine"), **bs
              ).pack(side="left", padx=(0, 6))
    tk.Button(btn_f, text="🗑  Delete File",
              bg="#1a0f00", fg=AMBER, activebackground="#2a1a00",
              command=lambda: _do("delete"), **bs
              ).pack(side="left", padx=(0, 6))
    tk.Button(btn_f, text="✓  Mark Safe",
              bg="#0a1a0a", fg=TEAL2, activebackground="#0f2a0f",
              command=lambda: _do("allow"), **bs
              ).pack(side="left", padx=(0, 6))
    tk.Button(btn_f, text="📄  Report",
              bg="#0a1020", fg=BLUE, activebackground="#0d1a30",
              command=lambda: _open_report(), **bs
              ).pack(side="right")

    def _open_report():
        try:
            reports = sorted(SANDBOX_DIR.glob("*_report.json"))
            if reports:
                os.startfile(str(reports[-1]))
        except Exception:
            pass

    # SCROLLABLE CONTENT — fills remaining space above button bar
    canvas = tk.Canvas(root, bg=BG, highlightthickness=0)
    scrollbar = tk.Scrollbar(root, orient="vertical",
                             command=canvas.yview)
    canvas.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side="right", fill="y")
    canvas.pack(side="left", fill="both", expand=True)

    scroll_frame = tk.Frame(canvas, bg=BG)
    canvas_window = canvas.create_window(
        (0, 0), window=scroll_frame, anchor="nw")

    def _on_resize(event):
        canvas.itemconfig(canvas_window, width=event.width)
    canvas.bind("<Configure>", _on_resize)

    def _on_frame_configure(event):
        canvas.configure(scrollregion=canvas.bbox("all"))
    scroll_frame.bind("<Configure>", _on_frame_configure)

    # mouse wheel scroll
    def _on_mousewheel(event):
        canvas.yview_scroll(int(-1*(event.delta/120)), "units")
    canvas.bind_all("<MouseWheel>", _on_mousewheel)

    # ── Content inside scroll_frame ───────────────────────────────────────
    f = scroll_frame  # shorthand

    # top accent bar
    tk.Frame(f, bg=color, height=5).pack(fill="x")

    # header
    hdr = tk.Frame(f, bg=BG3, padx=16, pady=12)
    hdr.pack(fill="x")
    tk.Label(hdr, text=f"Sandbox Analysis — {verdict.upper()}",
             font=("Consolas", 13, "bold"),
             fg=color, bg=BG3).pack(side="left")
    tk.Label(hdr, text=f"  Risk score: {score}/100",
             font=("Consolas", 11), fg=TEXT3, bg=BG3).pack(side="left")

    # file info
    info = tk.Frame(f, bg=BG2, padx=16, pady=10)
    info.pack(fill="x")

    def row(lbl, val, fg=TEXT, mono=False):
        r = tk.Frame(info, bg=BG2)
        r.pack(fill="x", pady=2)
        tk.Label(r, text=lbl, font=("Consolas", 9),
                 fg=TEXT3, bg=BG2, width=14,
                 anchor="w").pack(side="left")
        tk.Label(r, text=str(val)[:65],
                 font=("Consolas", 10) if mono else ("Segoe UI", 10),
                 fg=fg, bg=BG2, anchor="w").pack(
                     side="left", fill="x", expand=True)

    row("File:",    report["file"],  AMBER)
    row("Format:",  f"{fmt} / {arch}")
    row("Size:",    f"{report['size_bytes']:,} bytes")
    row("Entropy:", f"{report['entropy']:.3f} / 8.0",
        AMBER if report["entropy"] > 7.0 else TEXT)
    row("Verdict:", verdict.upper(), color)
    row("Sigs:",    f"{len(report['matched_signatures'])} matched",
        RED if report["matched_signatures"] else TEAL2)
    if report.get("suspicious_ips"):
        row("C2 IPs:", ", ".join(report["suspicious_ips"][:3]), RED)

    tk.Frame(f, bg="#1a2e28", height=1).pack(fill="x")

    # AI Analysis
    if ai:
        ai_f = tk.Frame(f, bg=BG3, padx=16, pady=10)
        ai_f.pack(fill="x")
        ai_hdr = tk.Frame(ai_f, bg=BG3)
        ai_hdr.pack(fill="x", pady=(0, 6))
        tk.Label(ai_hdr, text="🤖", font=("", 12),
                 fg=BLUE, bg=BG3).pack(side="left")
        tk.Label(ai_hdr, text="  AI Analysis",
                 font=("Segoe UI", 10, "bold"),
                 fg=BLUE, bg=BG3).pack(side="left")
        tk.Frame(ai_f, bg=BLUE, height=1).pack(fill="x", pady=(0, 6))
        for line in ai.split("\n"):
            if line.strip():
                is_verdict = any(kw in line for kw in
                                 ("VERDICT", "MALICIOUS", "SUSPICIOUS", "CLEAN"))
                tk.Label(ai_f, text=f"  › {line}",
                         font=("Segoe UI", 9,
                               "bold" if is_verdict else "normal"),
                         fg=color if is_verdict else TEXT2,
                         bg=BG3, wraplength=580,
                         justify="left", anchor="w").pack(fill="x", pady=1)

    tk.Frame(f, bg="#1a2e28", height=1).pack(fill="x")

    # Indicators
    ind_f = tk.Frame(f, bg=BG, padx=16, pady=8)
    ind_f.pack(fill="x")
    tk.Label(ind_f, text="Detection indicators:",
             font=("Segoe UI", 9, "bold"),
             fg=TEXT3, bg=BG).pack(anchor="w")
    for item in (inds or ["No suspicious indicators"]):
        tk.Label(ind_f, text=f"  › {str(item)[:75]}",
                 font=("Consolas", 8),
                 fg=TEXT2, bg=BG,
                 anchor="w").pack(fill="x", pady=1)

    root.mainloop()

    action = result[0]
    log.info(f"Sandbox user action: {action} on {report['file']}")

    if action == "quarantine":
        try:
            dest = (SANDBOX_DIR.parent / "quarantine" /
                    f"{int(time.time())}_sandbox_{Path(report['file']).name[:30]}")
            if path.exists():
                shutil.move(str(path), str(dest))
                log.info(f"Quarantined: {dest.name}")
        except Exception as e:
            log.error(f"Quarantine: {e}")
        if report["sha256"]:
            storage.update_learned("malicious_hashes", report["sha256"])
        storage.log_threat({
            "shield": "endpoint", "type": "file_quarantined",
            "file":   report["file"], "sha256": report["sha256"],
            "action": "quarantine", "score": score / 100,
        })

    elif action == "delete":
        try:
            if path.exists():
                path.unlink()
                log.info(f"Deleted: {path.name}")
        except Exception as e:
            log.error(f"Delete failed: {e}")
        if report["sha256"]:
            storage.update_learned("malicious_hashes", report["sha256"])
        storage.log_threat({
            "shield": "endpoint", "type": "file_deleted",
            "file":   report["file"], "sha256": report["sha256"],
            "action": "quarantine", "score": score / 100,
        })

    elif action == "allow":
        if report["sha256"]:
            storage.update_learned("safe_hashes", report["sha256"])
        storage.log_threat({
            "shield": "endpoint", "type": "file_allowed",
            "file":   report["file"], "action": "allowed_by_user",
            "score":  score / 100,
        })

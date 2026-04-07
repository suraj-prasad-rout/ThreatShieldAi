"""
ThreatShield AI — Endpoint Alert System
Buttons packed FIRST at bottom — always visible without resizing.
"""
import os
import time
import shutil
import threading
from pathlib import Path
from core.logger import get_logger

log = get_logger("endpoint_alert")
QUARANTINE_DIR = Path(__file__).parent.parent.parent / "data" / "quarantine"


def _endpoint_ai_summary(source, reason, risk_level, vt_result):
    lines = []
    src_map = {
        "virustotal":        "VirusTotal confirmed malware.",
        "known_hash":        "Previously confirmed malicious file — exact match in threat database.",
        "offline_heuristic": "Local AI heuristics detected suspicious patterns.",
        "usb_scan":          "Suspicious file found on USB/removable drive.",
        "ransomware_ext":    "File has ransomware-associated extension.",
    }
    if source in src_map:
        lines.append(src_map[source])
    if vt_result and vt_result.get("detections"):
        lines.append(
            f"{vt_result['detections']} security vendors flagged this file.")
    r = (reason or "").lower()
    if "keylogger" in r or "hook" in r:
        lines.append(
            "KEYLOGGER behavior — hooks keyboard to steal credentials.")
    if "ransomware" in r or "encrypt" in r:
        lines.append("RANSOMWARE behavior — may encrypt your documents.")
    if "trojan" in r or "injection" in r:
        lines.append("TROJAN behavior — injects code into other processes.")
    if "botnet" in r or "mirai" in r:
        lines.append("BOTNET/IoT malware — designed to attack other devices.")
    if "entropy" in r:
        lines.append("High entropy — packed to evade antivirus detection.")
    if risk_level == "high":
        lines.append("RECOMMENDATION: Quarantine immediately.")
    else:
        lines.append(
            "RECOMMENDATION: Sandbox analysis recommended before allowing.")
    return lines


def show_file_alert(path, sha256, source, reason, risk_level,
                    vt_result=None, storage=None, bus=None,
                    on_quarantine=None, on_sandbox=None, on_allow=None):
    import tkinter as tk

    BG = "#080c0b"
    BG2 = "#0d1412"
    BG3 = "#111918"
    RED = "#e8503a"
    RED2 = "#ff6b52"
    AMBER = "#f0a500"
    TEAL2 = "#25c791"
    BLUE = "#5b9de8"
    TEXT = "#c8ddd8"
    TEXT2 = "#7a9e98"
    TEXT3 = "#3a5e58"
    accent = RED if risk_level == "high" else AMBER
    verdict = "MALICIOUS" if risk_level == "high" else "SUSPICIOUS"

    root = tk.Tk()
    root.title("ThreatShield AI — Threat Detected")
    root.configure(bg=BG)
    root.attributes("-topmost", True)
    root.resizable(True, True)
    root.protocol("WM_DELETE_WINDOW", lambda: None)  # force decision

    def _flash():
        for _ in range(6):
            root.attributes("-topmost", True)
            root.focus_force()
            root.bell()
            time.sleep(0.3)
    threading.Thread(target=_flash, daemon=True).start()

    result = [None]
    def _do(action): result[0] = action; root.destroy()

    # ── BUTTONS — packed FIRST so always visible at bottom ────────────────
    tk.Frame(root, bg="#1a2e28", height=1).pack(side="bottom", fill="x")
    btn_area = tk.Frame(root, bg=BG2, padx=16, pady=12)
    btn_area.pack(side="bottom", fill="x")
    bs = {"font": ("Segoe UI", 9, "bold"), "relief": "flat",
          "padx": 11, "pady": 8, "cursor": "hand2", "bd": 0}
    tk.Button(btn_area, text="🔒  Quarantine",
              bg="#1a0808", fg=RED2, activebackground="#2a0a0a",
              command=lambda: _do("quarantine"), **bs
              ).pack(side="left", padx=(0, 5))
    tk.Button(btn_area, text="🗑  Delete File",
              bg="#1a0f00", fg=AMBER, activebackground="#2a1a00",
              command=lambda: _do("delete"), **bs
              ).pack(side="left", padx=(0, 5))
    tk.Button(btn_area, text="🔬  Sandbox",
              bg="#0a1020", fg=BLUE, activebackground="#0d1a30",
              command=lambda: _do("sandbox"), **bs
              ).pack(side="left", padx=(0, 5))
    tk.Button(btn_area, text="✓  Allow",
              bg=BG, fg=TEXT3, activebackground=BG3,
              command=lambda: _do("allow"), **bs
              ).pack(side="left")

    # ── SCROLLABLE CONTENT above buttons ─────────────────────────────────
    canvas = tk.Canvas(root, bg=BG, highlightthickness=0)
    vsb = tk.Scrollbar(root, orient="vertical", command=canvas.yview)
    canvas.configure(yscrollcommand=vsb.set)
    vsb.pack(side="right", fill="y")
    canvas.pack(side="left", fill="both", expand=True)
    sf = tk.Frame(canvas, bg=BG)
    win_id = canvas.create_window((0, 0), window=sf, anchor="nw")

    def _on_canvas_resize(e): canvas.itemconfig(win_id, width=e.width)
    canvas.bind("<Configure>", _on_canvas_resize)

    def _on_frame_change(e):
        canvas.configure(scrollregion=canvas.bbox("all"))
        content_h = canvas.bbox("all")[3]
        btn_h = btn_area.winfo_reqheight() + 40
        h = min(max(content_h + btn_h, 440), 700)
        root.geometry(f"580x{int(h)}")
    sf.bind("<Configure>", _on_frame_change)
    canvas.bind_all("<MouseWheel>",
                    lambda e: canvas.yview_scroll(int(-1*(e.delta/120)), "units"))

    # ── Content ───────────────────────────────────────────────────────────
    tk.Frame(sf, bg=accent, height=5).pack(fill="x")

    hdr = tk.Frame(sf, bg=BG2)
    hdr.pack(fill="x")
    icon_f = tk.Frame(hdr, bg=BG2, width=56, height=56)
    icon_f.pack(side="left", padx=14, pady=10)
    icon_f.pack_propagate(False)
    tk.Label(icon_f, text="⚠", font=("", 24),
             fg=accent, bg=BG2).place(relx=0.5, rely=0.5, anchor="center")
    title_f = tk.Frame(hdr, bg=BG2)
    title_f.pack(side="left", fill="y", pady=10)
    tk.Label(title_f, text="THREAT DETECTED",
             font=("Consolas", 12, "bold"), fg=accent, bg=BG2).pack(anchor="w")
    tk.Label(title_f, text=f"{verdict} FILE — Action Required",
             font=("Segoe UI", 9), fg=TEXT2, bg=BG2).pack(anchor="w")

    src_colors = {
        "virustotal":        (BLUE,  "VirusTotal"),
        "known_hash":        (RED,   "Known Malware"),
        "offline_heuristic": (AMBER, "AI Heuristic"),
        "usb_scan":          (AMBER, "USB Scan"),
        "ransomware_ext":    (RED,   "Ransomware"),
    }
    sc, sl = src_colors.get(source, (TEXT3, source.replace("_", " ").title()))
    badge = tk.Frame(hdr, bg=BG2)
    badge.pack(side="right", padx=14)
    tk.Label(badge, text=f" {sl} ", font=("Consolas", 9, "bold"),
             fg=sc, bg=BG3, padx=8, pady=3, relief="flat").pack()

    tk.Frame(sf, bg="#1a2e28", height=1).pack(fill="x")

    info = tk.Frame(sf, bg=BG2, padx=18, pady=10)
    info.pack(fill="x")

    def row(label, value, color=TEXT, mono=False):
        f = tk.Frame(info, bg=BG2)
        f.pack(fill="x", pady=2)
        tk.Label(f, text=label, font=("Consolas", 9), fg=TEXT3,
                 bg=BG2, width=12, anchor="w").pack(side="left")
        tk.Label(f, text=str(value)[:62],
                 font=("Consolas", 10) if mono else ("Segoe UI", 10),
                 fg=color, bg=BG2, anchor="w").pack(side="left", fill="x", expand=True)

    fname = Path(str(path)).name if path else "unknown"
    row("File:",     fname,    AMBER)
    row("Location:", str(Path(str(path)).parent)[:55], TEXT2)
    row("Threat:",   reason[:62], accent)
    row("Hash:",     sha256[:32]+"..." if sha256 else "N/A", TEXT3, mono=True)
    if vt_result and vt_result.get("detections"):
        row("VT Score:", f"{vt_result['detections']} vendors flagged", RED)

    tk.Frame(sf, bg="#1a2e28", height=1).pack(fill="x")

    warn = tk.Frame(sf, bg=BG3, padx=18, pady=8)
    warn.pack(fill="x")
    tk.Label(warn, text="⚠  Do NOT open or extract this file.",
             font=("Segoe UI", 9, "bold"), fg=accent, bg=BG3, anchor="w").pack(fill="x")
    tk.Label(warn, text="ThreatShield has blocked access. Choose an action below.",
             font=("Segoe UI", 9), fg=TEXT2, bg=BG3, anchor="w").pack(fill="x")

    if vt_result and vt_result.get("stats"):
        stats = vt_result["stats"]
        det_f = tk.Frame(sf, bg=BG2, padx=18, pady=8)
        det_f.pack(fill="x")
        tk.Label(det_f, text="Detection breakdown:", font=("Consolas", 9),
                 fg=TEXT3, bg=BG2).pack(anchor="w")
        sr = tk.Frame(det_f, bg=BG2)
        sr.pack(fill="x", pady=4)
        for key, color in [("malicious", RED), ("suspicious", AMBER),
                           ("harmless", TEAL2), ("undetected", TEXT3)]:
            val = stats.get(key, 0)
            if val > 0:
                f = tk.Frame(sr, bg=BG3, padx=8, pady=4)
                f.pack(side="left", padx=4)
                tk.Label(f, text=str(val), font=("Consolas", 12, "bold"),
                         fg=color, bg=BG3).pack()
                tk.Label(f, text=key.title(), font=("Consolas", 8),
                         fg=TEXT3, bg=BG3).pack()

    ai_lines = _endpoint_ai_summary(source, reason, risk_level, vt_result)
    if ai_lines:
        tk.Frame(sf, bg="#1a2e28", height=1).pack(fill="x")
        ai_f = tk.Frame(sf, bg="#0a0e0d", padx=18, pady=8)
        ai_f.pack(fill="x")
        ai_hdr = tk.Frame(ai_f, bg="#0a0e0d")
        ai_hdr.pack(fill="x", pady=(0, 5))
        tk.Label(ai_hdr, text="🤖", font=("", 11), fg=BLUE,
                 bg="#0a0e0d").pack(side="left")
        tk.Label(ai_hdr, text="  AI Analysis", font=("Segoe UI", 9, "bold"),
                 fg=BLUE, bg="#0a0e0d").pack(side="left")
        tk.Frame(ai_f, bg=BLUE, height=1).pack(fill="x", pady=(0, 5))
        for line in ai_lines:
            is_rec = "RECOMMENDATION" in line or "VERDICT" in line
            tk.Label(ai_f, text=f"  › {line}",
                     font=("Segoe UI", 8, "bold" if is_rec else "normal"),
                     fg=accent if is_rec else TEXT2,
                     bg="#0a0e0d", wraplength=520,
                     justify="left", anchor="w").pack(fill="x", pady=1)

    tk.Frame(sf, bg="#1a2e28", height=1).pack(fill="x")
    ind_f = tk.Frame(sf, bg=BG, padx=18, pady=8)
    ind_f.pack(fill="x")
    tk.Label(ind_f, text="Detection signals:", font=("Segoe UI", 8, "bold"),
             fg=TEXT3, bg=BG).pack(anchor="w", pady=(0, 4))
    indicators = []
    if reason:
        indicators.append(f"→ {reason}")
    if vt_result and vt_result.get("detections"):
        indicators.append(f"→ {vt_result['detections']} AV engines flagged")
    for ind in (indicators or ["→ Suspicious file detected"])[:6]:
        tk.Label(ind_f, text=f"  {ind[:70]}", font=("Consolas", 8),
                 fg=TEXT2, bg=BG, anchor="w").pack(fill="x", pady=1)

    root.mainloop()

    # ── execute action ────────────────────────────────────────────────────
    action = result[0]
    log.info(f"User action '{action}' on: {Path(str(path)).name}")

    if action == "quarantine" and on_quarantine:
        on_quarantine()
        if storage:
            storage.log_threat({"shield": "endpoint", "type": "file_quarantined",
                                "file": str(path), "sha256": sha256, "action": "quarantine"})
    elif action == "delete":
        try:
            fp = Path(str(path))
            if fp.exists():
                fp.unlink()
                log.info(f"Deleted: {fp.name}")
        except Exception as e:
            log.error(f"Delete: {e}")
        if storage:
            if sha256:
                storage.update_learned("malicious_hashes", sha256)
            storage.log_threat({"shield": "endpoint", "type": "file_deleted",
                                "file": str(path), "sha256": sha256, "action": "quarantine"})
    elif action == "sandbox" and on_sandbox:
        on_sandbox()
    elif action == "allow" and on_allow:
        on_allow()
        if storage:
            storage.log_threat({"shield": "endpoint", "type": "file_allowed",
                                "file": str(path), "sha256": sha256, "action": "allowed_by_user"})


def show_ransomware_alert(affected_files: list, storage=None, bus=None):
    import tkinter as tk
    BG = "#080c0b"
    BG2 = "#0d1412"
    RED = "#e8503a"
    RED2 = "#ff6b52"
    TEXT = "#c8ddd8"
    TEXT2 = "#7a9e98"
    TEXT3 = "#3a5e58"

    root = tk.Tk()
    root.title("ThreatShield AI — RANSOMWARE DETECTED")
    root.geometry("550x380")
    root.resizable(False, False)
    root.configure(bg=BG)
    root.attributes("-topmost", True)
    root.protocol("WM_DELETE_WINDOW", lambda: None)

    def _flash():
        for _ in range(10):
            root.attributes("-topmost", True)
            root.focus_force()
            root.bell()
            time.sleep(0.2)
    threading.Thread(target=_flash, daemon=True).start()

    tk.Frame(root, bg=RED, height=6).pack(fill="x")
    hdr = tk.Frame(root, bg=BG2, pady=14)
    hdr.pack(fill="x")
    tk.Label(hdr, text="🚨  RANSOMWARE BEHAVIOR DETECTED",
             font=("Consolas", 13, "bold"), fg=RED2, bg=BG2).pack()
    tk.Label(hdr, text=f"{len(affected_files)} files modified in the last 10 seconds",
             font=("Segoe UI", 9), fg=TEXT2, bg=BG2).pack(pady=(3, 0))
    tk.Frame(root, bg="#1a2e28", height=1).pack(fill="x")
    body = tk.Frame(root, bg=BG, padx=18, pady=10)
    body.pack(fill="both", expand=True)
    tk.Label(body, text="Affected files:", font=(
        "Consolas", 8), fg=TEXT3, bg=BG).pack(anchor="w")
    for f in affected_files[:5]:
        tk.Label(body, text=f"  → {str(f)[-55:]}", font=("Consolas", 8),
                 fg=TEXT, bg=BG, anchor="w").pack(fill="x")
    tk.Frame(root, bg="#1a2e28", height=1).pack(fill="x")
    btn = tk.Frame(root, bg=BG2, padx=16, pady=12)
    btn.pack(fill="x")
    bs = {"font": ("Segoe UI", 9, "bold"), "relief": "flat",
          "padx": 14, "pady": 8, "cursor": "hand2", "bd": 0}

    def _kill():
        try:
            import psutil
            for proc in psutil.process_iter(["pid", "name", "open_files"]):
                try:
                    for of in proc.open_files():
                        if any(str(f) in of.path for f in affected_files[:3]):
                            proc.kill()
                except Exception:
                    pass
        except Exception as e:
            log.error(f"Kill: {e}")
        root.destroy()

    tk.Button(btn, text="☠  Kill Suspicious Processes",
              bg="#1a0808", fg=RED2, command=_kill, **bs).pack(side="left", padx=(0, 8))
    tk.Button(btn, text="Dismiss", bg=BG, fg=TEXT3,
              command=root.destroy, **bs).pack(side="right")
    root.mainloop()

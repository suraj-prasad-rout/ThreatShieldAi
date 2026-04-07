"""
ThreatShield AI — Email Phishing Alert Window
Fixed: AI summary added with full themed UI
"""
import threading
import time
from pathlib import Path
from core.logger import get_logger

log = get_logger("alert_window")


def show_alert(email_data: dict, storage, bus,
               on_block_sender=None, on_block_domain=None,
               on_mark_safe=None, on_dismiss=None):
    import tkinter as tk

    BG = "#080c0b"
    BG2 = "#0d1412"
    BG3 = "#111918"
    RED = "#e8503a"
    RED2 = "#ff6b52"
    AMBER = "#f0a500"
    TEAL = "#1d9e75"
    TEAL2 = "#25c791"
    BLUE = "#5b9de8"
    TEXT = "#c8ddd8"
    TEXT2 = "#7a9e98"
    TEXT3 = "#3a5e58"

    score = int(email_data.get("score", 0) * 100)
    subject = email_data.get("subject", "Unknown")[:55]
    sender = email_data.get("sender", "Unknown")[:55]
    to_addr = email_data.get("to", "")[:45]
    signals = email_data.get("signals", []) or email_data.get("reasons", [])
    urls = email_data.get("urls_found", [])
    url_str = urls[0] if urls else ""
    queued = email_data.get("queued", 0)

    # AI summary generation
    def _make_ai_summary():
        lines = []
        score_val = email_data.get("score", 0)
        sigs_lower = [s.lower() for s in signals]

        if any("credential" in s for s in sigs_lower):
            lines.append(
                "Credential harvesting attempt — email tries to steal login details.")
        if any("urgency" in s or "suspend" in s for s in sigs_lower):
            lines.append(
                "Urgency/threat tactics — creates false pressure to act immediately.")
        if any("nlp" in s for s in sigs_lower):
            lines.append("NLP patterns match known phishing templates.")
        if any("learned" in s or "keyword" in s for s in sigs_lower):
            lines.append(
                "Matches known phishing keywords from threat database.")
        if url_str:
            domain = url_str.split("/")[2] if "/" in url_str[8:] else url_str
            lines.append(f"Suspicious URL found: {domain[:40]}")
        if any("mismatch" in s or "reply" in s for s in sigs_lower):
            lines.append(
                "Sender/reply-to mismatch — common email spoofing technique.")

        if score_val >= 0.8:
            lines.append(
                f"HIGH CONFIDENCE PHISHING (score {score}/100) — Block sender recommended.")
        elif score_val >= 0.6:
            lines.append(
                f"LIKELY PHISHING (score {score}/100) — Review carefully before trusting.")
        else:
            lines.append(
                f"SUSPICIOUS (score {score}/100) — Possible phishing, verify sender.")

        return lines

    ai_lines = _make_ai_summary()

    root = tk.Tk()
    root.title("ThreatShield AI — Phishing Detected")
    root.configure(bg=BG)
    root.attributes("-topmost", True)
    root.attributes("-toolwindow", False)
    root.resizable(False, False)

    # calculate height based on content
    base_height = 420 + len(ai_lines) * 20
    root.geometry(f"480x{base_height}")

    result = [None]

    def _do(action):
        result[0] = action
        root.destroy()

    # top accent bar
    tk.Frame(root, bg=RED, height=4).pack(fill="x")

    # header
    hdr = tk.Frame(root, bg=BG2)
    hdr.pack(fill="x")
    icon_f = tk.Frame(hdr, bg=BG2, width=50, height=50)
    icon_f.pack(side="left", padx=12, pady=10)
    icon_f.pack_propagate(False)
    tk.Label(icon_f, text="⚠", font=("", 22),
             fg=RED, bg=BG2).place(relx=0.5, rely=0.5, anchor="center")
    title_f = tk.Frame(hdr, bg=BG2)
    title_f.pack(side="left", fill="y", pady=10)
    tk.Label(title_f, text="Phishing Detected",
             font=("Consolas", 13, "bold"),
             fg=RED, bg=BG2).pack(anchor="w")
    tk.Label(title_f, text="Suspicious email intercepted",
             font=("Segoe UI", 9), fg=TEXT2, bg=BG2).pack(anchor="w")
    # score badge
    score_c = RED if score >= 70 else AMBER if score >= 40 else TEAL2
    sc_f = tk.Frame(hdr, bg=BG2)
    sc_f.pack(side="right", padx=12)
    tk.Label(sc_f, text=str(score), font=("Consolas", 20, "bold"),
             fg=score_c, bg=BG2).pack()
    tk.Label(sc_f, text="/100", font=("Consolas", 8),
             fg=TEXT3, bg=BG2).pack()

    tk.Frame(root, bg="#1a2e28", height=1).pack(fill="x")

    # email details
    info = tk.Frame(root, bg=BG2, padx=16, pady=10)
    info.pack(fill="x")

    def info_row(label, value, fg=TEXT2):
        f = tk.Frame(info, bg=BG2)
        f.pack(fill="x", pady=2)
        tk.Label(f, text=label, font=("Consolas", 9),
                 fg=TEXT3, bg=BG2, width=10, anchor="w").pack(side="left")
        tk.Label(f, text=str(value)[:55],
                 font=("Segoe UI", 10), fg=fg, bg=BG2,
                 anchor="w").pack(side="left", fill="x", expand=True)

    if to_addr:
        info_row("To:", to_addr)
    info_row("Subject:", subject, AMBER)
    info_row("From:", sender, RED2)
    if url_str:
        info_row("URL found", url_str[:50], TEAL2)

    tk.Frame(root, bg="#1a2e28", height=1).pack(fill="x")

    # signals
    sig_f = tk.Frame(root, bg=BG, padx=16, pady=8)
    sig_f.pack(fill="x")
    for sig in signals[:3]:
        tk.Label(sig_f, text=f"  • {sig[:60]}",
                 font=("Segoe UI", 8), fg=TEXT2, bg=BG,
                 anchor="w").pack(fill="x")
    remaining = len(signals) - 3
    if remaining > 0:
        tk.Label(sig_f, text=f"  + {remaining} more signals",
                 font=("Segoe UI", 8), fg=TEXT3, bg=BG,
                 anchor="w").pack(fill="x")

    # ── AI Summary section ────────────────────────────────────────────────
    if ai_lines:
        tk.Frame(root, bg="#1a2e28", height=1).pack(fill="x")
        ai_f = tk.Frame(root, bg=BG3, padx=16, pady=8)
        ai_f.pack(fill="x")
        # header row
        ai_hdr = tk.Frame(ai_f, bg=BG3)
        ai_hdr.pack(fill="x", pady=(0, 6))
        tk.Label(ai_hdr, text="🤖", font=("", 12),
                 fg=BLUE, bg=BG3).pack(side="left")
        tk.Label(ai_hdr, text="  AI Threat Analysis",
                 font=("Segoe UI", 9, "bold"),
                 fg=BLUE, bg=BG3).pack(side="left")
        # divider
        tk.Frame(ai_f, bg=BLUE, height=1).pack(fill="x", pady=(0, 6))
        # each AI line
        for line in ai_lines:
            row_f = tk.Frame(ai_f, bg=BG3)
            row_f.pack(fill="x", pady=1)
            # color the verdict line differently
            is_verdict = ("VERDICT" in line or "CONFIDENCE" in line
                          or "PHISHING" in line or "SUSPICIOUS" in line)
            line_color = score_c if is_verdict else TEXT2
            tk.Label(row_f, text=f"  › {line}",
                     font=("Segoe UI", 8,
                           "bold" if is_verdict else "normal"),
                     fg=line_color, bg=BG3,
                     wraplength=430, justify="left",
                     anchor="w").pack(fill="x")

    tk.Frame(root, bg="#1a2e28", height=1).pack(fill="x")

    # action buttons
    btn_f = tk.Frame(root, bg=BG2, padx=14, pady=12)
    btn_f.pack(fill="x")
    bs = {"font": ("Segoe UI", 9, "bold"), "relief": "flat",
          "padx": 10, "pady": 7, "cursor": "hand2", "bd": 0}

    tk.Button(btn_f, text="Block Sender",
              bg="#1a0808", fg=RED2,
              activebackground="#2a0a0a",
              command=lambda: _do("block_sender"), **bs
              ).pack(side="left", padx=(0, 6))
    tk.Button(btn_f, text="Block Domain",
              bg="#0f1a10", fg=TEAL2,
              activebackground="#1a2e28",
              command=lambda: _do("block_domain"), **bs
              ).pack(side="left", padx=(0, 6))
    tk.Button(btn_f, text="Mark Safe",
              bg=BG, fg=TEXT2,
              activebackground=BG3,
              command=lambda: _do("mark_safe"), **bs
              ).pack(side="left", padx=(0, 6))
    tk.Button(btn_f, text="Dismiss",
              bg=BG, fg=TEXT3,
              activebackground=BG3,
              command=lambda: _do("dismiss"), **bs
              ).pack(side="left")

    if queued > 0:
        tk.Label(btn_f,
                 text=f"  {queued} more alerts queued",
                 font=("Segoe UI", 8), fg=TEXT3, bg=BG2
                 ).pack(side="right")

    root.mainloop()

    # execute action
    action = result[0] or "dismiss"
    log.info(f"Email alert action: {action}")

    if action == "block_sender" and on_block_sender:
        r = on_block_sender()
        log.info(f"Block sender result: {r}")
    elif action == "block_domain" and on_block_domain:
        r = on_block_domain()
        log.info(f"Block domain result: {r}")
    elif action == "mark_safe" and on_mark_safe:
        r = on_mark_safe()
        log.info(f"Mark safe result: {r}")
    elif action == "dismiss" and on_dismiss:
        on_dismiss()

    return action

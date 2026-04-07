"""
ThreatShield AI — Chrome Extension Installation Page
Embedded in the main app UI.
"""
import os
import sys
import subprocess
import platform
import webbrowser
from pathlib import Path

IS_WIN = platform.system() == "Windows"
FONT   = "Segoe UI" if IS_WIN else "Ubuntu"
MONO   = "Consolas"  if IS_WIN else "Monospace"

BG    = "#0a0f0e"
BG2   = "#0f1614"
BG3   = "#141e1c"
BG4   = "#1a2826"
TEAL  = "#1d9e75"
TEAL2 = "#25c791"
TEAL3 = "#0f6e56"
RED   = "#e8503a"
AMBER = "#f0a500"
BLUE  = "#5b9de8"
TEXT  = "#d4e8e4"
TEXT2 = "#7a9e98"
TEXT3 = "#3a5e58"
BORD  = "#1e2e2c"

def F(s, b=False): return (FONT, s, "bold") if b else (FONT, s)
def M(s, b=False): return (MONO, s, "bold") if b else (MONO, s)


def build_extension_page(app, parent, base_dir: Path):
    """Build the extension installation page."""
    import customtkinter as ctk

    sc = ctk.CTkScrollableFrame(parent, fg_color=BG, corner_radius=0,
                                 scrollbar_button_color=BG4)
    sc.pack(fill="both", expand=True)

    # header
    hdr = ctk.CTkFrame(sc, fg_color=BG)
    hdr.pack(fill="x", padx=24, pady=(20,0))
    ctk.CTkLabel(hdr, text="Chrome Extension",
                 font=F(22,True), text_color=TEXT,
                 anchor="w").pack(side="left")
    ctk.CTkFrame(sc, fg_color=BORD, height=1,
                 corner_radius=0).pack(fill="x", padx=24, pady=(10,0))

    # status card
    status_card = ctk.CTkFrame(sc, fg_color=BG2, corner_radius=12,
                                border_width=1, border_color=BORD)
    status_card.pack(fill="x", padx=24, pady=(16,0))
    ctk.CTkFrame(status_card, fg_color=TEAL, width=4,
                 corner_radius=0).pack(side="left", fill="y")
    si = ctk.CTkFrame(status_card, fg_color=BG2)
    si.pack(fill="both", expand=True, padx=16, pady=14)

    ctk.CTkLabel(si, text="What the extension does",
                 font=F(14,True), text_color=TEXT,
                 anchor="w").pack(anchor="w")
    for item in [
        "🛡  Blocks malicious URLs before the page loads",
        "🚫  Cancels dangerous file downloads automatically",
        "⚠  Shows threat warnings with Block / Allow options",
        "🔔  Desktop notifications for every blocked threat",
        "◈  Check any page manually from the popup",
    ]:
        ctk.CTkLabel(si, text=item, font=F(12),
                     text_color=TEXT2, anchor="w").pack(
                         anchor="w", pady=2)

    # installation steps
    ctk.CTkLabel(sc, text="INSTALLATION STEPS",
                 font=M(10), text_color=TEXT3, anchor="w").pack(
                     fill="x", padx=24, pady=(20,8))

    ext_dir = base_dir / "extension"

    steps = [
        (1, BLUE,  "Open Chrome Extensions Page",
         "Opens chrome://extensions in your browser",
         lambda: webbrowser.open("chrome://extensions")),
        (2, AMBER, "Enable Developer Mode",
         "Toggle 'Developer mode' in the top-right corner of the Extensions page.\nThis is required to install unpacked extensions.",
         None),
        (3, TEAL2, "Open Extension Folder",
         "Click 'Load unpacked', then select the folder that opens below.",
         lambda: _open_folder(ext_dir)),
        (4, TEAL,  "Select the Extension Folder",
         f"Navigate to and select this folder:\n{ext_dir}",
         lambda: _copy_path(app, ext_dir)),
    ]

    for num, color, title, desc, cmd in steps:
        card = ctk.CTkFrame(sc, fg_color=BG2, corner_radius=12,
                            border_width=1, border_color=BORD)
        card.pack(fill="x", padx=24, pady=5)
        ctk.CTkFrame(card, fg_color=color, width=4,
                     corner_radius=0).pack(side="left", fill="y")
        inner = ctk.CTkFrame(card, fg_color=BG2)
        inner.pack(fill="both", expand=True, padx=16, pady=12)

        top = ctk.CTkFrame(inner, fg_color=BG2)
        top.pack(fill="x")

        # step number
        nb = ctk.CTkFrame(top, fg_color=color, width=28, height=28,
                          corner_radius=14)
        nb.pack(side="left", padx=(0,10))
        nb.pack_propagate(False)
        ctk.CTkLabel(nb, text=str(num), font=M(11,True),
                     text_color=BG).place(relx=0.5,rely=0.5,anchor="center")

        ctk.CTkLabel(top, text=title, font=F(13,True),
                     text_color=TEXT, anchor="w").pack(side="left")

        if cmd:
            ctk.CTkButton(top, text="Open ↗", font=F(11),
                          width=70, height=26,
                          fg_color=BG4, text_color=color,
                          hover_color=BG3, corner_radius=4,
                          command=cmd).pack(side="right")

        ctk.CTkLabel(inner, text=desc, font=F(11),
                     text_color=TEXT2, justify="left",
                     anchor="w").pack(anchor="w", pady=(6,0))

    # verify section
    verify_card = ctk.CTkFrame(sc, fg_color=BG2, corner_radius=12,
                                border_width=1, border_color=BORD)
    verify_card.pack(fill="x", padx=24, pady=(16,0))
    ctk.CTkFrame(verify_card, fg_color=TEAL, width=4,
                 corner_radius=0).pack(side="left", fill="y")
    vi = ctk.CTkFrame(verify_card, fg_color=BG2)
    vi.pack(fill="both", expand=True, padx=16, pady=14)

    top_v = ctk.CTkFrame(vi, fg_color=BG2)
    top_v.pack(fill="x")
    ctk.CTkLabel(top_v, text="Verify Installation",
                 font=F(14,True), text_color=TEXT,
                 anchor="w").pack(side="left")
    ctk.CTkButton(top_v, text="Test Connection",
                  font=F(11), width=130, height=28,
                  fg_color=TEAL3, text_color=TEAL2,
                  hover_color=TEAL, corner_radius=6,
                  command=lambda: _test_connection(app)
                  ).pack(side="right")

    ctk.CTkLabel(vi,
                 text="After installing, click 'Test Connection' to verify the extension\n"
                      "can communicate with ThreatShield. You should see the shield icon\n"
                      "in your Chrome toolbar.",
                 font=F(12), text_color=TEXT2,
                 justify="left", anchor="w").pack(anchor="w", pady=(6,0))

    # path display
    path_card = ctk.CTkFrame(sc, fg_color=BG3, corner_radius=8,
                              border_width=1, border_color=BORD)
    path_card.pack(fill="x", padx=24, pady=(12,24))
    pi = ctk.CTkFrame(path_card, fg_color=BG3)
    pi.pack(fill="x", padx=12, pady=10)
    ctk.CTkLabel(pi, text="Extension folder:",
                 font=M(9), text_color=TEXT3).pack(side="left")
    ctk.CTkLabel(pi, text=str(ext_dir),
                 font=M(10), text_color=TEXT2).pack(side="left", padx=8)
    ctk.CTkButton(pi, text="Copy", font=M(9),
                  width=50, height=22,
                  fg_color=BG4, text_color=TEXT2,
                  hover_color=BG3, corner_radius=4,
                  command=lambda: _copy_path(app, ext_dir)
                  ).pack(side="right")

    return sc


def _open_folder(path: Path):
    if platform.system() == "Windows":
        os.startfile(str(path))
    else:
        subprocess.Popen(["xdg-open", str(path)])


def _copy_path(app, path: Path):
    app.clipboard_clear()
    app.clipboard_append(str(path))
    from tkinter import messagebox
    messagebox.showinfo("Copied",
        f"Path copied to clipboard:\n{path}\n\n"
        "Now in Chrome:\n"
        "1. Click 'Load unpacked'\n"
        "2. Paste this path and press Enter")


def _test_connection(app):
    import threading
    def _check():
        try:
            import requests
            r = requests.get("http://localhost:8766/status", timeout=3)
            if r.ok:
                app.after(0, lambda: __import__("tkinter.messagebox",
                    fromlist=["messagebox"]).messagebox.showinfo(
                    "✓ Connected",
                    "ThreatShield daemon is running.\n"
                    "Extension can communicate with ThreatShield.\n\n"
                    "Look for the shield icon in Chrome toolbar."))
            else:
                raise Exception(f"HTTP {r.status_code}")
        except Exception as e:
            app.after(0, lambda: __import__("tkinter.messagebox",
                fromlist=["messagebox"]).messagebox.showerror(
                "Connection Failed",
                f"Cannot reach ThreatShield daemon.\n{e}\n\n"
                "Make sure ThreatShield is running."))
    threading.Thread(target=_check, daemon=True).start()

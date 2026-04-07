"""
ThreatShield AI — Native Desktop Application
Fixes:
- No screen flickering: UI updates only when data changes
- Threat detail panel on click
- Separate DNS blocklist and email/web blocklist
- EXE works: reads from shared storage file on disk
"""
from core.logger import get_logger
from core.storage import Storage
from tkinter import messagebox
import customtkinter as ctk
import sys
import os
import time
import json
import platform
import subprocess
import threading
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BASE_DIR))


log = get_logger("ui")

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

BG = "#0a0f0e"
BG2 = "#0f1614"
BG3 = "#141e1c"
BG4 = "#1a2826"
TEAL = "#1d9e75"
TEAL2 = "#25c791"
TEAL3 = "#0f6e56"
RED = "#e8503a"
AMBER = "#f0a500"
BLUE = "#5b9de8"
TEXT = "#d4e8e4"
TEXT2 = "#7a9e98"
TEXT3 = "#3a5e58"
BORD = "#1e2e2c"

IS_WIN = platform.system() == "Windows"
FONT = "Segoe UI" if IS_WIN else "Ubuntu"
MONO = "Consolas" if IS_WIN else "Monospace"


def F(s, b=False): return (FONT, s, "bold") if b else (FONT, s)
def M(s, b=False): return (MONO, s, "bold") if b else (MONO, s)


class ThreatShieldApp(ctk.CTk):
    def __init__(self, storage: Storage):
        super().__init__()
        self.storage = storage
        self._page = "dashboard"
        self._start = time.time()
        self._filter = "all"

        # anti-flicker: track last known state
        self._last_threat_count = -1
        self._last_blocked_count = -1

        self.title("ThreatShield AI")
        self.geometry("1240x720")
        self.minsize(1000, 600)
        self.configure(fg_color=BG)
        self._build()
        self._refresh_all()
        self._schedule()

    def _build(self):
        self._make_sidebar().pack(side="left", fill="y")
        ctk.CTkFrame(self, fg_color=BORD, width=1,
                     corner_radius=0).pack(side="left", fill="y")
        self._content = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        self._content.pack(side="left", fill="both", expand=True)
        self._build_pages()

    def _make_sidebar(self):
        sb = ctk.CTkFrame(self, fg_color=BG2, corner_radius=0, width=220)
        sb.pack_propagate(False)

        logo = ctk.CTkFrame(sb, fg_color=BG3, corner_radius=0, height=64)
        logo.pack(fill="x")
        logo.pack_propagate(False)
        lrow = ctk.CTkFrame(logo, fg_color=BG3)
        lrow.place(relx=0.5, rely=0.5, anchor="center")
        box = ctk.CTkFrame(lrow, fg_color=TEAL3, width=32, height=32,
                           corner_radius=8, border_width=1, border_color=TEAL)
        box.pack(side="left", padx=(0, 10))
        box.pack_propagate(False)
        ctk.CTkLabel(box, text="🛡", font=("", 16),
                     text_color=TEAL2).place(relx=0.5, rely=0.5, anchor="center")
        col = ctk.CTkFrame(lrow, fg_color=BG3)
        col.pack(side="left")
        ctk.CTkLabel(col, text="ThreatShield",
                     font=F(13, True), text_color=TEXT).pack(anchor="w")
        ctk.CTkLabel(col, text="AI Protection  v2.0",
                     font=M(9), text_color=TEXT3).pack(anchor="w")

        ctk.CTkFrame(sb, fg_color=BORD, height=1,
                     corner_radius=0).pack(fill="x")

        nav = ctk.CTkFrame(sb, fg_color=BG2)
        nav.pack(fill="x", padx=10, pady=10)
        ctk.CTkLabel(nav, text="NAVIGATION", font=M(9),
                     text_color=TEXT3, anchor="w").pack(fill="x", pady=(0, 6))

        self._nav_btns = {}
        for page, icon, label in [
            ("dashboard",  "⬡", "Dashboard"),
            ("threats",    "◈", "Threat Log"),
            ("quarantine", "⬠", "Quarantine"),
            ("shields",    "◉", "Shields"),
            ("email_mgr",  "✉", "Email Accounts"),
            ("blocklist",  "⊘", "Block List"),
            ("dns_block",  "◌", "DNS Block List"),
            ("extension",  "⬡", "Chrome Extension"),
            ("community",  "◈", "Community"),
            ("submissions", "📤", "My Submissions"),
            ("settings",   "◎", "Settings"),
        ]:
            btn = ctk.CTkButton(
                nav, text=f"  {icon}   {label}",
                font=F(12), anchor="w", height=34,
                corner_radius=8, fg_color=BG2,
                text_color=TEXT2, hover_color=BG4,
                border_width=0,
                command=lambda p=page: self._nav(p))
            btn.pack(fill="x", pady=1)
            self._nav_btns[page] = btn

        ctk.CTkFrame(sb, fg_color=BG2).pack(fill="both", expand=True)
        ctk.CTkFrame(sb, fg_color=BORD, height=1,
                     corner_radius=0).pack(fill="x")

        bot = ctk.CTkFrame(sb, fg_color=BG2)
        bot.pack(fill="x", padx=10, pady=8)

        sf = ctk.CTkFrame(bot, fg_color=BG3, corner_radius=20,
                          border_width=1, border_color=TEAL3)
        sf.pack(fill="x", pady=(0, 6))
        sr = ctk.CTkFrame(sf, fg_color=BG3)
        sr.pack(padx=10, pady=5)
        ctk.CTkLabel(sr, text="●", font=F(10),
                     text_color=TEAL2).pack(side="left", padx=(0, 6))
        ctk.CTkLabel(sr, text="All systems active",
                     font=F(11), text_color=TEXT2).pack(side="left")

        st = ctk.CTkFrame(bot, fg_color=BG3, corner_radius=8)
        st.pack(fill="x", pady=(0, 4))
        ctk.CTkLabel(st, text="Start with system",
                     font=F(11), text_color=TEXT2).pack(
                         side="left", padx=(12, 0), pady=7)
        self._startup_sw = ctk.CTkSwitch(
            st, text="", width=44, height=22,
            fg_color=BG4, progress_color=TEAL,
            command=self._toggle_startup)
        self._startup_sw.pack(side="right", padx=10)

        self._clock = ctk.CTkLabel(bot, text="", font=M(10), text_color=TEXT3)
        self._clock.pack(pady=(2, 0))
        return sb

    # ── pages ─────────────────────────────────────────────────────────────
    def _build_pages(self):
        self._pages = {}
        for name in ["dashboard", "threats", "quarantine", "shields",
                     "email_mgr", "blocklist", "dns_block",
                     "extension", "community", "submissions", "settings"]:
            f = ctk.CTkFrame(self._content, fg_color=BG, corner_radius=0)
            f.place(x=0, y=0, relwidth=1, relheight=1)
            self._pages[name] = f

        self._build_dashboard(self._pages["dashboard"])
        self._build_threats(self._pages["threats"])
        self._build_quarantine(self._pages["quarantine"])
        self._build_shields(self._pages["shields"])
        self._build_email_mgr(self._pages["email_mgr"])
        self._build_blocklist(self._pages["blocklist"])
        self._build_dns_block(self._pages["dns_block"])
        self._build_extension(self._pages["extension"])
        self._build_community(self._pages["community"])
        self._build_submissions(self._pages["submissions"])
        self._build_settings(self._pages["settings"])

    def _hdr(self, parent, title, sub=""):
        h = ctk.CTkFrame(parent, fg_color=BG)
        h.pack(fill="x", padx=24, pady=(20, 0))
        ctk.CTkLabel(h, text=title, font=F(22, True),
                     text_color=TEXT, anchor="w").pack(side="left")
        if sub:
            ctk.CTkLabel(h, text=f"  {sub}", font=F(12),
                         text_color=TEXT3).pack(side="left", pady=(4, 0))
        ctk.CTkFrame(parent, fg_color=BORD, height=1,
                     corner_radius=0).pack(fill="x", padx=24, pady=(10, 0))

    def _card(self, parent):
        return ctk.CTkFrame(parent, fg_color=BG2, corner_radius=12,
                            border_width=1, border_color=BORD)

    def _accent_card(self, parent, color):
        outer = ctk.CTkFrame(parent, fg_color=BG2, corner_radius=12,
                             border_width=1, border_color=BORD)
        ctk.CTkFrame(outer, fg_color=color, width=4,
                     corner_radius=0).pack(side="left", fill="y")
        inner = ctk.CTkFrame(outer, fg_color=BG2)
        inner.pack(fill="both", expand=True, padx=16, pady=14)
        return outer, inner

    # ── DASHBOARD ─────────────────────────────────────────────────────────
    def _build_dashboard(self, page):
        sc = ctk.CTkScrollableFrame(page, fg_color=BG, corner_radius=0,
                                    scrollbar_button_color=BG4)
        sc.pack(fill="both", expand=True)
        self._hdr(sc, "Dashboard", "Real-time protection overview")

        sr = ctk.CTkFrame(sc, fg_color=BG)
        sr.pack(fill="x", padx=24, pady=16)
        self._s = {}
        for key, label, color in [
            ("total",  "THREATS BLOCKED", TEAL2),
            ("today",  "TODAY",           RED),
            ("uptime", "SESSION UPTIME",  AMBER),
            ("shields", "SHIELDS ACTIVE",  BLUE),
        ]:
            c = self._card(sr)
            c.pack(side="left", fill="x", expand=True, padx=5)
            ctk.CTkFrame(c, fg_color=color, height=3,
                         corner_radius=0).pack(fill="x")
            ctk.CTkLabel(c, text=label, font=M(9),
                         text_color=TEXT3, anchor="w").pack(
                             anchor="w", padx=14, pady=(10, 0))
            lbl = ctk.CTkLabel(c, text="—", font=(MONO, 26, "bold"),
                               text_color=color, anchor="w")
            lbl.pack(anchor="w", padx=14, pady=(2, 14))
            self._s[key] = lbl

        pr = ctk.CTkFrame(sc, fg_color=BG)
        pr.pack(fill="x", padx=24, pady=(0, 8))
        self._pills = {}
        for key, label, icon in [
            ("email",    "Email Shield",    "✉"),
            ("web",      "Web Shield",      "🌐"),
            ("endpoint", "Endpoint Shield", "💾"),
        ]:
            c = self._card(pr)
            c.pack(side="left", fill="x", expand=True, padx=5)
            row = ctk.CTkFrame(c, fg_color=BG2)
            row.pack(padx=14, pady=10)
            ctk.CTkLabel(row, text=f"{icon}  {label}",
                         font=F(12), text_color=TEXT2).pack(side="left")
            dot = ctk.CTkLabel(row, text="● ON", font=M(9), text_color=TEAL2)
            dot.pack(side="right", padx=(10, 0))
            self._pills[key] = dot

        ctk.CTkLabel(sc, text="RECENT THREATS", font=M(10),
                     text_color=TEXT3, anchor="w").pack(
                         fill="x", padx=24, pady=(8, 6))
        self._dash_list = self._card(sc)
        self._dash_list.pack(fill="x", padx=24, pady=(0, 20))

    # ── THREATS PAGE with click-to-expand ─────────────────────────────────
    def _build_threats(self, page):
        # split: left=list, right=detail
        page.grid_columnconfigure(0, weight=3)
        page.grid_columnconfigure(1, weight=2)
        page.grid_rowconfigure(1, weight=1)

        hdr = ctk.CTkFrame(page, fg_color=BG)
        hdr.grid(row=0, column=0, columnspan=2,
                 sticky="ew", padx=24, pady=(20, 0))
        ctk.CTkLabel(hdr, text="Threat Log",
                     font=F(22, True), text_color=TEXT).pack(side="left")

        self._filter_btns = {}
        fbr = ctk.CTkFrame(hdr, fg_color=BG)
        fbr.pack(side="right")
        for label, val in [("All", "all"), ("Email", "email"),
                           ("Web", "web"), ("Endpoint", "endpoint")]:
            b = ctk.CTkButton(
                fbr, text=label, font=F(11),
                width=68, height=26, corner_radius=6,
                fg_color=TEAL if val == "all" else BG3,
                text_color=TEXT if val == "all" else TEXT2,
                hover_color=BG4,
                command=lambda v=val: self._set_filter(v))
            b.pack(side="left", padx=2)
            self._filter_btns[val] = b

        ctk.CTkFrame(page, fg_color=BORD, height=1,
                     corner_radius=0).grid(row=0, column=0, columnspan=2,
                                           sticky="sew", padx=24, pady=(58, 0))

        self._threat_scroll = ctk.CTkScrollableFrame(
            page, fg_color=BG2, corner_radius=12,
            border_width=1, border_color=BORD,
            scrollbar_button_color=BG4)
        self._threat_scroll.grid(row=1, column=0, sticky="nsew",
                                 padx=(24, 6), pady=12)

        # detail panel
        self._detail_panel = ctk.CTkFrame(
            page, fg_color=BG2, corner_radius=12,
            border_width=1, border_color=BORD)
        self._detail_panel.grid(row=1, column=1, sticky="nsew",
                                padx=(6, 24), pady=12)
        ctk.CTkLabel(self._detail_panel,
                     text="Click a threat\nto see details",
                     font=F(13), text_color=TEXT3,
                     justify="center").place(relx=0.5, rely=0.5, anchor="center")

    # ── QUARANTINE ────────────────────────────────────────────────────────
    def _build_quarantine(self, page):
        self._hdr(page, "Quarantine", "Files isolated by ThreatShield")
        self._q_scroll = ctk.CTkScrollableFrame(
            page, fg_color=BG2, corner_radius=12,
            border_width=1, border_color=BORD,
            scrollbar_button_color=BG4)
        self._q_scroll.pack(fill="both", expand=True, padx=24, pady=12)

    # ── SHIELDS ───────────────────────────────────────────────────────────
    def _build_shields(self, page):
        sc = ctk.CTkScrollableFrame(page, fg_color=BG, corner_radius=0,
                                    scrollbar_button_color=BG4)
        sc.pack(fill="both", expand=True)
        self._hdr(sc, "Shield Control")
        self._shield_sw = {}
        self._shield_lbl = {}
        for key, name, icon, desc, color in [
            ("email",    "Email Shield",    "✉",
             "Monitors all accounts for phishing and malicious links.", BLUE),
            ("web",      "Web Shield",      "🌐",
             "Intercepts malicious URLs via Chrome extension + DNS filtering.", AMBER),
            ("endpoint", "Endpoint Shield", "💾",
             "Scans files, archives and USB drives for malware.", TEAL2),
        ]:
            outer, inner = self._accent_card(sc, color)
            outer.pack(fill="x", padx=24, pady=8)
            top = ctk.CTkFrame(inner, fg_color=BG2)
            top.pack(fill="x")
            ctk.CTkLabel(top, text=f"{icon}   {name}",
                         font=F(14, True), text_color=TEXT,
                         anchor="w").pack(side="left")
            active = key in self.storage.config.get("active_shields", [])
            sw = ctk.CTkSwitch(top, text="", width=46, height=24,
                               fg_color=BG4, progress_color=color,
                               command=lambda k=key: self._toggle_shield(k))
            sw.pack(side="right")
            if active:
                sw.select()
            self._shield_sw[key] = sw
            st = ctk.CTkLabel(top,
                              text="ACTIVE" if active else "DISABLED",
                              font=M(9),
                              text_color=TEAL2 if active else TEXT3)
            st.pack(side="right", padx=(0, 10))
            self._shield_lbl[key] = st
            ctk.CTkLabel(inner, text=desc, font=F(12),
                         text_color=TEXT2, wraplength=700,
                         justify="left", anchor="w").pack(fill="x", pady=(6, 0))

    # ── EMAIL MANAGER ─────────────────────────────────────────────────────
    def _build_email_mgr(self, page):
        sc = ctk.CTkScrollableFrame(page, fg_color=BG, corner_radius=0,
                                    scrollbar_button_color=BG4)
        sc.pack(fill="both", expand=True)
        hdr = ctk.CTkFrame(sc, fg_color=BG)
        hdr.pack(fill="x", padx=24, pady=(20, 0))
        ctk.CTkLabel(hdr, text="Email Accounts",
                     font=F(22, True), text_color=TEXT,
                     anchor="w").pack(side="left")
        ctk.CTkButton(hdr, text="+ Add Account",
                      font=F(12), width=130, height=32,
                      fg_color=TEAL3, text_color=TEAL2,
                      hover_color=TEAL, corner_radius=8,
                      command=self._add_email_account).pack(side="right")
        ctk.CTkFrame(sc, fg_color=BORD, height=1,
                     corner_radius=0).pack(fill="x", padx=24, pady=(10, 0))

        info, ii = self._accent_card(sc, BLUE)
        info.pack(fill="x", padx=24, pady=(12, 0))
        ctk.CTkLabel(ii,
                     text="Add Gmail or any IMAP account.\n"
                          "Use an App Password — not your real password.",
                     font=F(12), text_color=TEXT2,
                     justify="left", anchor="w").pack(anchor="w")
        ctk.CTkButton(ii, text="Get Gmail App Password ↗",
                      font=F(11), width=200, height=26,
                      fg_color=BG4, text_color=BLUE,
                      hover_color=BG3, corner_radius=6,
                      command=lambda: self._open_url(
                          "https://myaccount.google.com/apppasswords")
                      ).pack(anchor="w", pady=(6, 0))

        self._email_list = ctk.CTkFrame(sc, fg_color=BG)
        self._email_list.pack(fill="x", padx=24, pady=12)

    def _refresh_email_mgr(self):
        for w in self._email_list.winfo_children():
            w.destroy()
        accounts = self.storage.config.get("email_accounts", [])
        if not accounts:
            ctk.CTkLabel(self._email_list,
                         text="No accounts configured.\nClick '+ Add Account'.",
                         font=F(13), text_color=TEXT3,
                         justify="center").pack(pady=32)
            return
        for i, acc in enumerate(accounts):
            outer, inner = self._accent_card(self._email_list, BLUE)
            outer.pack(fill="x", pady=6)
            top = ctk.CTkFrame(inner, fg_color=BG2)
            top.pack(fill="x")
            ctk.CTkLabel(top, text=f"✉   {acc.get('imap_user', '')}",
                         font=F(13, True), text_color=TEXT,
                         anchor="w").pack(side="left")
            ctk.CTkButton(top, text="Remove", font=F(11),
                          width=70, height=26, fg_color=BG4,
                          text_color=RED, hover_color="#2a0808",
                          corner_radius=4,
                          command=lambda idx=i: self._remove_email(idx)
                          ).pack(side="right")
            ctk.CTkLabel(inner,
                         text=f"IMAP: {acc.get('imap_host', '')}   "
                         f"Password: {'●●●●●●' if acc.get('imap_pass') else 'NOT SET'}",
                         font=M(10), text_color=TEXT2,
                         anchor="w").pack(anchor="w", pady=(6, 0))

    def _add_email_account(self):
        d = ctk.CTkToplevel(self)
        d.title("Add Email Account")
        d.geometry("440x340")
        d.configure(fg_color=BG)
        d.attributes("-topmost", True)
        d.grab_set()

        ctk.CTkLabel(d, text="Add Email Account",
                     font=F(16, True), text_color=TEXT).pack(pady=(20, 4))
        ctk.CTkLabel(d, text="Use Gmail App Password, not your real password.",
                     font=F(11), text_color=TEXT3).pack(pady=(0, 12))

        fields = {}
        for label, key, placeholder, show in [
            ("Email Address", "imap_user", "you@gmail.com",       ""),
            ("App Password",  "imap_pass", "xxxx xxxx xxxx xxxx", "●"),
            ("IMAP Server",   "imap_host", "imap.gmail.com",      ""),
        ]:
            ctk.CTkLabel(d, text=label, font=F(12),
                         text_color=TEXT2, anchor="w").pack(
                             fill="x", padx=24, pady=(4, 0))
            e = ctk.CTkEntry(d, placeholder_text=placeholder,
                             font=F(12), height=34, show=show,
                             fg_color=BG3, border_color=BORD, text_color=TEXT)
            e.pack(fill="x", padx=24, pady=(2, 4))
            fields[key] = e

        def _detect(event=None):
            em = fields["imap_user"].get().strip()
            host_map = {
                "@gmail.com":   "imap.gmail.com",
                "@outlook.com": "imap-mail.outlook.com",
                "@hotmail.com": "imap-mail.outlook.com",
                "@yahoo.com":   "imap.mail.yahoo.com",
            }
            for domain, host in host_map.items():
                if domain in em:
                    fields["imap_host"].delete(0, "end")
                    fields["imap_host"].insert(0, host)
                    break
        fields["imap_user"].bind("<FocusOut>", _detect)
        fields["imap_host"].insert(0, "imap.gmail.com")

        def _save():
            user = fields["imap_user"].get().strip()
            pwd = fields["imap_pass"].get().strip()
            host = fields["imap_host"].get().strip()
            if not user or not pwd or not host:
                messagebox.showerror("Error", "All fields required.", parent=d)
                return
            accounts = self.storage.config.get("email_accounts", [])
            if any(a.get("imap_user") == user for a in accounts):
                messagebox.showerror(
                    "Error", f"{user} already added.", parent=d)
                return
            accounts.append(
                {"imap_host": host, "imap_user": user, "imap_pass": pwd})
            self.storage.config["email_accounts"] = accounts
            self.storage.save("config.json", self.storage.config)
            d.destroy()
            self._refresh_email_mgr()
            messagebox.showinfo("Added", f"✓ {user} added successfully.")
        ctk.CTkButton(d, text="Save Account",
                      font=F(13, True), height=36,
                      fg_color=TEAL, text_color="#fff",
                      hover_color=TEAL3, corner_radius=8,
                      command=_save).pack(fill="x", padx=24, pady=12)

    def _remove_email(self, idx):
        accounts = self.storage.config.get("email_accounts", [])
        if idx >= len(accounts):
            return
        user = accounts[idx].get("imap_user", "")
        if not messagebox.askyesno("Remove", f"Remove {user}?"):
            return
        accounts.pop(idx)
        self.storage.config["email_accounts"] = accounts
        self.storage.save("config.json", self.storage.config)
        self._refresh_email_mgr()

    # ── BLOCK LIST (email/web senders/domains) ────────────────────────────
    def _build_blocklist(self, page):
        self._hdr(page, "Block List", "Blocked senders and web domains")
        self._bl_scroll = ctk.CTkScrollableFrame(
            page, fg_color=BG2, corner_radius=12,
            border_width=1, border_color=BORD,
            scrollbar_button_color=BG4)
        self._bl_scroll.pack(fill="both", expand=True, padx=24, pady=12)

    # ── DNS BLOCK LIST ────────────────────────────────────────────────────
    def _build_dns_block(self, page):
        self._hdr(page, "DNS Block List", "Domains blocked at DNS level")
        info = ctk.CTkFrame(page, fg_color=BG3, corner_radius=8,
                            border_width=1, border_color=BORD)
        info.pack(fill="x", padx=24, pady=(8, 0))
        ctk.CTkLabel(info,
                     text="  ◌  These domains are blocked at DNS level — "
                          "no device on your network can access them.",
                     font=F(11), text_color=TEXT2, anchor="w").pack(
                         fill="x", padx=4, pady=8)
        self._dns_scroll = ctk.CTkScrollableFrame(
            page, fg_color=BG2, corner_radius=12,
            border_width=1, border_color=BORD,
            scrollbar_button_color=BG4)
        self._dns_scroll.pack(fill="both", expand=True, padx=24, pady=(8, 12))

    # ── EXTENSION ─────────────────────────────────────────────────────────
    def _build_community(self, page):
        sc = ctk.CTkScrollableFrame(page, fg_color=BG, corner_radius=0,
                                    scrollbar_button_color=BG4)
        sc.pack(fill="both", expand=True)
        hdr = ctk.CTkFrame(sc, fg_color=BG)
        hdr.pack(fill="x", padx=24, pady=(20, 0))
        ctk.CTkLabel(hdr, text="Community Intelligence",
                     font=F(22, True), text_color=TEXT, anchor="w").pack(side="left")
        self._sync_btn = ctk.CTkButton(hdr, text="⟳  Sync Now",
                                       font=F(12), width=110, height=32,
                                       fg_color=TEAL3, text_color=TEAL2,
                                       hover_color=TEAL, corner_radius=8,
                                       command=self._manual_sync)
        self._sync_btn.pack(side="right")
        ctk.CTkFrame(sc, fg_color=BORD, height=1,
                     corner_radius=0).pack(fill="x", padx=24, pady=(10, 0))
        # enable toggle
        tog, ti = self._accent_card(sc, TEAL)
        tog.pack(fill="x", padx=24, pady=(14, 0))
        top_t = ctk.CTkFrame(ti, fg_color=BG2)
        top_t.pack(fill="x")
        ctk.CTkLabel(top_t, text="Enable Community Sharing",
                     font=F(14, True), text_color=TEXT, anchor="w").pack(side="left")
        self._community_toggle = ctk.CTkSwitch(
            top_t, text="", width=46, height=24,
            fg_color=BG4, progress_color=TEAL,
            command=self._toggle_community_sharing)
        self._community_toggle.pack(side="right")
        on = self.storage.config.get("community_reporting", False)
        if on:
            self._community_toggle.select()
        ctk.CTkLabel(ti,
                     text="Confirmed threats submitted to URLhaus automatically. "
                          "No personal data — only URLs and hashes.",
                     font=F(12), text_color=TEXT2,
                     wraplength=700, justify="left", anchor="w").pack(fill="x", pady=(6, 0))
        # stat cards
        sr = ctk.CTkFrame(sc, fg_color=BG)
        sr.pack(fill="x", padx=24, pady=14)
        self._comm_stats = {}
        for key, label, color in [
            ("submitted", "SUBMITTED", TEAL2), ("received", "RECEIVED", BLUE),
                ("domains", "DOMAINS BLOCKED", AMBER), ("hashes", "HASHES KNOWN", RED)]:
            c = self._card(sr)
            c.pack(side="left", fill="x", expand=True, padx=5)
            ctk.CTkFrame(c, fg_color=color, height=3,
                         corner_radius=0).pack(fill="x")
            ctk.CTkLabel(c, text=label, font=M(9), text_color=TEXT3,
                         anchor="w").pack(anchor="w", padx=14, pady=(8, 0))
            lbl = ctk.CTkLabel(c, text="—", font=(MONO, 22, "bold"),
                               text_color=color, anchor="w")
            lbl.pack(anchor="w", padx=14, pady=(2, 12))
            self._comm_stats[key] = lbl
        # feeds
        ctk.CTkLabel(sc, text="THREAT FEEDS", font=M(10),
                     text_color=TEXT3, anchor="w").pack(fill="x", padx=24, pady=(0, 8))
        for color, icon, name, desc, url, needs_key in [
            (RED,   "⬡", "URLhaus",
             "Malware URL database. 100k+ active threats. No key to pull, key optional to submit.",
             "https://urlhaus.abuse.ch", False),
            (AMBER, "◈", "ThreatFox",
             "IOC feed: malware hashes, C2 domains and IPs from global analysts.",
             "https://threatfox.abuse.ch", False),
            (TEAL2, "◉", "Feodo Tracker",
             "Botnet C2 IP blocklist — Emotet, TrickBot, Dridex, QakBot. No key needed.",
             "https://feodotracker.abuse.ch", False),
            (BLUE,  "◌", "SSL Blacklist",
             "IPs with malicious SSL certificates. Updated every 5 minutes.",
             "https://sslbl.abuse.ch", False),
            (AMBER, "◈", "Cybercrime Tracker",
             "Crimeware C2 domains tracked by security researchers worldwide.",
             "http://cybercrime-tracker.net", False),
            (TEAL,  "⬡", "SANS ISC DShield",
             "Top attacking IP subnets compiled by SANS Internet Storm Center.",
             "https://feeds.dshield.org", False),
            (BLUE,  "◌", "OpenPhish",
             "Community phishing URL feed, no key needed.",
             "https://openphish.com", False),
        ]:
            outer, inner = self._accent_card(sc, color)
            outer.pack(fill="x", padx=24, pady=4)
            top_f = ctk.CTkFrame(inner, fg_color=BG2)
            top_f.pack(fill="x")
            ctk.CTkLabel(top_f, text=f"{icon}  {name}", font=F(12, True),
                         text_color=TEXT, anchor="w").pack(side="left")
            ctk.CTkButton(top_f, text="Visit ↗", font=F(10), width=55, height=22,
                          fg_color=BG4, text_color=color, hover_color=BG3,
                          corner_radius=4, command=lambda u=url: self._open_url(u)
                          ).pack(side="right")
            key_lbl = "🔓 No key needed" if not needs_key else "🔑 Key required"
            key_col = TEAL2 if not needs_key else AMBER
            ctk.CTkLabel(top_f, text=key_lbl, font=M(9),
                         text_color=key_col).pack(side="right", padx=8)
            ctk.CTkLabel(inner, text=desc, font=F(11),
                         text_color=TEXT2, anchor="w").pack(anchor="w", pady=(3, 0))
        # API keys
        # How to get key instructions
        how, hi = self._accent_card(sc, BLUE)
        how.pack(fill="x", padx=24, pady=(8, 0))
        ctk.CTkLabel(hi, text="How to get your Auth-Key",
                     font=F(13, True), text_color=TEXT, anchor="w").pack(anchor="w")
        steps = [
            "1. Go to  https://auth.abuse.ch  and sign in with Google, GitHub or LinkedIn",
            "2. Click your username (top right) → Your Account",
            "3. Scroll to the Optional section → click Generate Auth-Key",
            "4. Copy the key and paste it in URLhaus Auth-Key below",
            "5. The SAME auth.abuse.ch account gives you URLhaus + MalwareBazaar keys separately",
        ]
        for step in steps:
            ctk.CTkLabel(hi, text=step, font=F(11),
                         text_color=TEXT2, anchor="w").pack(anchor="w", pady=1)
        ctk.CTkButton(hi, text="Open auth.abuse.ch ↗", font=F(11),
                      width=160, height=26, fg_color=BG4,
                      text_color=BLUE, hover_color=BG3, corner_radius=4,
                      command=lambda: self._open_url("https://auth.abuse.ch/")
                      ).pack(anchor="w", pady=(6, 0))

        ctk.CTkLabel(sc, text="API KEYS", font=M(10),
                     text_color=TEXT3, anchor="w").pack(fill="x", padx=24, pady=(14, 8))
        for label, key, link in [
            ("URLhaus Auth-Key  (from auth.abuse.ch → Your Account → Auth-Key)",
             "urlhaus_api_key",
             "https://auth.abuse.ch/"),
            ("MalwareBazaar API Key  (same auth.abuse.ch account — separate key)",
             "malwarebazaar_api_key",
             "https://auth.abuse.ch/"),
        ]:
            outer_k, inner_k = self._accent_card(sc, TEAL3)
            outer_k.pack(fill="x", padx=24, pady=5)
            ctk.CTkLabel(inner_k, text=label, font=F(13, True),
                         text_color=TEXT, anchor="w").pack(anchor="w")
            row_k = ctk.CTkFrame(inner_k, fg_color=BG2)
            row_k.pack(fill="x", pady=(6, 0))
            entry_k = ctk.CTkEntry(row_k, font=M(11), height=32,
                                   placeholder_text=f"Paste {label}",
                                   fg_color=BG3, border_color=BORD,
                                   text_color=TEXT, show="●")
            entry_k.pack(side="left", fill="x", expand=True, padx=(0, 8))
            cur = self.storage.config.get(key, "")
            if cur:
                entry_k.insert(0, cur)
            ctk.CTkButton(row_k, text="Save", font=F(11), width=60, height=32,
                          fg_color=TEAL3, text_color=TEAL2, hover_color=TEAL,
                          corner_radius=4,
                          command=lambda k=key, e=entry_k: self._save_api_key(
                              k, e)
                          ).pack(side="right", padx=(0, 4))
            if key == "urlhaus_api_key":
                ctk.CTkButton(row_k, text="Verify", font=F(11), width=60, height=32,
                              fg_color=BG4, text_color=BLUE, hover_color=BG3,
                              corner_radius=4,
                              command=lambda e=entry_k: self._verify_urlhaus_key(
                                  e)
                              ).pack(side="right", padx=(0, 4))
            ctk.CTkButton(inner_k, text="Get key ↗", font=F(10), width=80, height=22,
                          fg_color=BG4, text_color=TEAL2, hover_color=BG3,
                          corner_radius=4, command=lambda l=link: self._open_url(l)
                          ).pack(anchor="w", pady=(4, 0))
        # info note
        note, ni = self._accent_card(sc, AMBER)
        note.pack(fill="x", padx=24, pady=(0, 0))
        ctk.CTkLabel(ni,
                     text="ℹ  PhishTank has disabled new registrations (March 2026). "
                          "MalwareBazaar is the recommended replacement for hash submission.",
                     font=F(11), text_color=TEXT2,
                     wraplength=700, justify="left",
                     anchor="w").pack(fill="x")

        # activity log
        ctk.CTkLabel(sc, text="ACTIVITY LOG", font=M(10),
                     text_color=TEXT3, anchor="w").pack(fill="x", padx=24, pady=(14, 8))
        self._activity_log = self._card(sc)
        self._activity_log.pack(fill="x", padx=24, pady=(0, 20))

    def _r_community(self):
        try:
            blocked = self.storage.learned_patterns.get("blocked_senders", [])
            hashes = self.storage.learned_patterns.get("malicious_hashes", [])
            self._comm_stats["submitted"].configure(text="—")
            self._comm_stats["received"].configure(text="—")
            self._comm_stats["domains"].configure(text=str(len(blocked)))
            self._comm_stats["hashes"].configure(text=str(len(hashes)))
            on = self.storage.config.get("community_reporting", False)
            self._community_toggle.select() if on else self._community_toggle.deselect()
            for w in self._activity_log.winfo_children():
                w.destroy()
            ctk.CTkLabel(self._activity_log,
                         text="  Sync runs every 6 hours automatically. Use 'Sync Now' to pull latest.",
                         font=F(12), text_color=TEXT3).pack(padx=14, pady=14)
        except Exception:
            pass

    def _toggle_community_sharing(self):
        cur = self.storage.config.get("community_reporting", False)
        self.storage.config["community_reporting"] = not cur
        self.storage.save("config.json", self.storage.config)

    def _save_api_key(self, key: str, entry):
        val = entry.get().strip()
        self.storage.config[key] = val
        self.storage.save("config.json", self.storage.config)
        messagebox.showinfo("Saved", f"API key saved.")

    def _verify_urlhaus_key(self, entry):
        key = entry.get().strip()
        if not key:
            messagebox.showerror("Error", "Paste your URLhaus API key first.")
            return

        def _check():
            try:
                import requests
                r = requests.post(
                    "https://urlhaus-api.abuse.ch/v1/url/",
                    data={"token": key,
                          "url": "https://example.com/test_verify",
                          "threat": "malware_download",
                          "tags[]": "test"},
                    timeout=8)
                if r.status_code == 401:
                    self.after(0, lambda: messagebox.showerror(
                        "Key Invalid",
                        "HTTP 401 — Key rejected by URLhaus.\n\n"
                        "1. Go to urlhaus.abuse.ch and sign in\n"
                        "2. Click your username → API Access\n"
                        "3. Copy the FULL key (no spaces/newlines)\n"
                        "4. Your account must be email-verified"))
                elif r.status_code == 200:
                    status = r.json().get("query_status", "")
                    if status in ("is_new", "duplicate", "invalid_url", "no_valid_url"):
                        self.after(0, lambda: messagebox.showinfo(
                            "Key Valid",
                            "✓ URLhaus API key is working correctly.\n"
                            "You can now submit threats to the community."))
                    else:
                        self.after(0, lambda: messagebox.showinfo(
                            "Key Checked", f"Response: {status}"))
                else:
                    self.after(0, lambda: messagebox.showwarning(
                        "Unknown", f"HTTP {r.status_code} — try again later."))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Error", str(e)))
        import threading
        threading.Thread(target=_check, daemon=True).start()

    def _manual_sync(self):
        self._sync_btn.configure(text="Syncing...", state="disabled")

        def _do():
            try:
                from utils.community_reporter import CommunityReporter
                cr = CommunityReporter(self.storage)
                n1 = cr.pull_urlhaus_feed()
                n2 = cr.pull_threatfox_feed()
                n3 = cr.pull_openphish_feed()
                n4 = cr.pull_feodo_tracker()
                n5 = cr.pull_ssl_blacklist()
                n6 = cr.pull_cybercrime_tracker()
                n7 = cr.pull_dshield_ips()
                total = n1+n2+n3+n4+n5+n6+n7
                self.after(0, lambda: self._sync_btn.configure(
                    text="⟳  Sync Now", state="normal"))
                msg = (
                    f"URLhaus:          +{n1} domains\n"
                    f"ThreatFox:        +{n2} IOCs\n"
                    f"OpenPhish:        +{n3} phishing\n"
                    f"Feodo Tracker:    +{n4} botnet IPs\n"
                    f"SSL Blacklist:    +{n5} cert IPs\n"
                    f"Cybercrime Track: +{n6} C2 domains\n"
                    f"SANS DShield:     +{n7} attack IPs\n\n"
                    f"Total: +{total} new indicators added")
                self.after(0, lambda: messagebox.showinfo(
                    "Sync Complete", "✓ Sync complete\n\n" + msg))
                self.after(0, self._r_community)
            except Exception as e:
                self.after(0, lambda: self._sync_btn.configure(
                    text="⟳  Sync Now", state="normal"))
                self.after(0, lambda: messagebox.showerror("Error", str(e)))
        threading.Thread(target=_do, daemon=True).start()

    def _build_submissions(self, page):
        sc = ctk.CTkScrollableFrame(page, fg_color=BG, corner_radius=0,
                                    scrollbar_button_color=BG4)
        sc.pack(fill="both", expand=True)
        hdr = ctk.CTkFrame(sc, fg_color=BG)
        hdr.pack(fill="x", padx=24, pady=(20, 0))
        ctk.CTkLabel(hdr, text="My Submissions",
                     font=F(22, True), text_color=TEXT,
                     anchor="w").pack(side="left")
        ctk.CTkFrame(sc, fg_color=BORD, height=1,
                     corner_radius=0).pack(fill="x", padx=24, pady=(10, 0))

        # info card
        info, ii = self._accent_card(sc, TEAL)
        info.pack(fill="x", padx=24, pady=(12, 0))
        ctk.CTkLabel(ii,
                     text="Threats you have shared with URLhaus, ThreatFox and the community. "
                          "Your submissions help protect other ThreatShield users worldwide.",
                     font=F(12), text_color=TEXT2,
                     justify="left", anchor="w").pack(anchor="w")

        self._sub_list = ctk.CTkFrame(sc, fg_color=BG)
        self._sub_list.pack(fill="x", padx=24, pady=12)

    def _r_submissions(self):
        for w in self._sub_list.winfo_children():
            w.destroy()

        # collect posted threats from threat log
        posted = [t for t in self.storage.threat_log
                  if t.get("community_posted")]

        if not posted:
            ctk.CTkLabel(self._sub_list,
                         text="No submissions yet. Use Post to Community in Threat Log.",
                         font=F(13), text_color=TEXT3,
                         justify="center").pack(pady=40)
            return

        # header
        ctk.CTkLabel(self._sub_list,
                     text=f"{len(posted)} threat(s) shared with community",
                     font=M(10), text_color=TEAL2,
                     anchor="w").pack(anchor="w", pady=(0, 8))

        for t in reversed(posted):
            outer, inner = self._accent_card(self._sub_list, TEAL)
            outer.pack(fill="x", pady=5)

            shield = t.get("shield", "?").upper()
            sh_c = {"EMAIL": BLUE, "WEB": AMBER,
                    "ENDPOINT": TEAL2}.get(shield, TEXT3)
            ts = self._ttime(t)
            subj = (t.get("subject") or t.get("url") or
                    t.get("file") or t.get("type", ""))[:55]
            score = int((t.get("score") or 0)*100)

            top = ctk.CTkFrame(inner, fg_color=BG2)
            top.pack(fill="x")
            # shield badge
            bf = ctk.CTkFrame(top, fg_color=BG4, corner_radius=4, width=76)
            bf.pack(side="left", padx=(0, 8))
            bf.pack_propagate(False)
            ctk.CTkLabel(bf, text=shield, font=M(9),
                         text_color=sh_c).pack(fill="both", expand=True)
            ctk.CTkLabel(top, text=subj or "Unknown threat",
                         font=F(12, True), text_color=TEXT,
                         anchor="w").pack(side="left", fill="x", expand=True)
            ctk.CTkLabel(top, text=f"{ts}",
                         font=M(9), text_color=TEXT3).pack(side="right")

            # details row
            det = ctk.CTkFrame(inner, fg_color=BG2)
            det.pack(fill="x", pady=(6, 0))

            if t.get("url"):
                ctk.CTkLabel(det, text=f"URL: {t['url'][:60]}",
                             font=M(9), text_color=TEXT2,
                             anchor="w").pack(anchor="w")
            if t.get("sha256"):
                ctk.CTkLabel(det, text=f"Hash: {t['sha256'][:32]}...",
                             font=M(9), text_color=TEXT2,
                             anchor="w").pack(anchor="w")
            if score:
                ctk.CTkLabel(det, text=f"Risk score: {score}/100",
                             font=M(9), text_color=RED if score >= 70 else AMBER,
                             anchor="w").pack(anchor="w")

            # posted badge
            ctk.CTkLabel(inner, text="✓ Shared with URLhaus community",
                         font=F(10), text_color=TEAL2,
                         anchor="w").pack(anchor="w", pady=(6, 0))

    def _build_extension(self, page):
        try:
            from ui.extension_page import build_extension_page
            build_extension_page(self, page, BASE_DIR)
        except Exception as e:
            ctk.CTkLabel(page, text=f"Extension page error: {e}",
                         font=M(11), text_color=RED).pack(pady=40)

    # ── SETTINGS ──────────────────────────────────────────────────────────
    def _build_settings(self, page):
        sc = ctk.CTkScrollableFrame(page, fg_color=BG, corner_radius=0,
                                    scrollbar_button_color=BG4)
        sc.pack(fill="both", expand=True)
        self._hdr(sc, "Settings")

        for color, title, attr, desc, cmd in [
            (TEAL, "Start with system", "_set_sw",
             "Start automatically on boot.", self._toggle_startup),
            (BLUE, "Community Reporting", "_comm_sw",
             "Manually report threats to URLhaus.", self._toggle_community),
        ]:
            outer, inner = self._accent_card(sc, color)
            outer.pack(fill="x", padx=24, pady=8)
            top = ctk.CTkFrame(inner, fg_color=BG2)
            top.pack(fill="x")
            ctk.CTkLabel(top, text=title, font=F(14, True),
                         text_color=TEXT, anchor="w").pack(side="left")
            sw = ctk.CTkSwitch(top, text="", width=46, height=24,
                               fg_color=BG4, progress_color=color,
                               command=cmd)
            sw.pack(side="right")
            setattr(self, attr, sw)
            ctk.CTkLabel(inner, text=desc, font=F(12),
                         text_color=TEXT2, anchor="w").pack(
                             fill="x", pady=(4, 0))

        # VT key
        outer_v, inner_v = self._accent_card(sc, AMBER)
        outer_v.pack(fill="x", padx=24, pady=8)
        ctk.CTkLabel(inner_v, text="VirusTotal API Key",
                     font=F(14, True), text_color=TEXT, anchor="w").pack(anchor="w")
        ctk.CTkLabel(inner_v,
                     text="Required for online detection. Free key at virustotal.com",
                     font=F(12), text_color=TEXT2, anchor="w").pack(
                         anchor="w", pady=(4, 8))
        vt_row = ctk.CTkFrame(inner_v, fg_color=BG2)
        vt_row.pack(fill="x")
        self._vt_entry = ctk.CTkEntry(
            vt_row, placeholder_text="Paste VirusTotal API key",
            font=M(11), height=34, fg_color=BG3,
            border_color=BORD, text_color=TEXT, show="●")
        self._vt_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        current_key = self.storage.config.get("virustotal_api_key", "")
        if current_key:
            self._vt_entry.insert(0, current_key)
        ctk.CTkButton(vt_row, text="Save", font=F(12),
                      width=70, height=34, fg_color=TEAL3,
                      text_color=TEAL2, hover_color=TEAL,
                      corner_radius=6,
                      command=self._save_vt_key).pack(side="right")

        # sys info
        outer3, inner3 = self._accent_card(sc, AMBER)
        outer3.pack(fill="x", padx=24, pady=8)
        ctk.CTkLabel(inner3, text="System Information",
                     font=F(14, True), text_color=TEXT, anchor="w").pack(anchor="w")
        self._sys_info = ctk.CTkLabel(inner3, text="", font=M(11),
                                      text_color=TEXT2, justify="left", anchor="w")
        self._sys_info.pack(anchor="w", pady=(8, 0))

        # open data folder
        outer4, inner4 = self._accent_card(sc, RED)
        outer4.pack(fill="x", padx=24, pady=8)
        top4 = ctk.CTkFrame(inner4, fg_color=BG2)
        top4.pack(fill="x")
        ctk.CTkLabel(top4, text="Data & Files", font=F(14, True),
                     text_color=TEXT, anchor="w").pack(side="left")
        ctk.CTkButton(top4, text="Open Folder", font=F(12),
                      width=120, height=28, fg_color=BG3,
                      text_color=TEXT2, hover_color=BG4, corner_radius=6,
                      command=self._open_data).pack(side="right")
        ctk.CTkLabel(inner4, text="Access logs, quarantine and config.",
                     font=F(12), text_color=TEXT2, anchor="w").pack(
                         anchor="w", pady=(4, 0))

    # ── navigation ────────────────────────────────────────────────────────
    def _nav(self, page):
        self._page = page
        for n, b in self._nav_btns.items():
            b.configure(
                fg_color=BG4 if n == page else BG2,
                text_color=TEAL2 if n == page else TEXT2,
                border_width=1 if n == page else 0,
                border_color=TEAL3 if n == page else BG2)
        self._pages[page].lift()
        self._refresh_page(page)

    # ── SMART REFRESH — no flicker ─────────────────────────────────────────
    def _schedule(self):
        """Check for new data every 3s but only redraw if data changed."""
        self._smart_refresh()
        self.after(3000, self._schedule)

    def _smart_refresh(self):
        """Only reload UI if threat count or blocked list changed."""
        self._tick()

        # reload from disk (fast JSON read)
        try:
            new_threats = self.storage._load("threat_log.json", [])
            new_blocked = self.storage._load("learned_patterns.json", {}).get(
                "blocked_senders", [])
        except Exception:
            new_threats = self.storage.threat_log
            new_blocked = self.storage.learned_patterns.get(
                "blocked_senders", [])

        threat_count = len(new_threats)
        blocked_count = len(new_blocked)

        # update internal state
        self.storage.threat_log = new_threats
        self.storage.learned_patterns = self.storage._load(
            "learned_patterns.json",
            self.storage._default_patterns())

        # only redraw if counts changed
        data_changed = (threat_count != self._last_threat_count or
                        blocked_count != self._last_blocked_count)

        if data_changed:
            self._last_threat_count = threat_count
            self._last_blocked_count = blocked_count
            self._refresh_stats()
            # only refresh current page if data changed
            self._refresh_page(self._page)
        else:
            # always update uptime without redrawing everything
            self._update_uptime_only()

    def _update_uptime_only(self):
        up = int(time.time()-self._start)
        self._s["uptime"].configure(text=self._fmt_up(up))

    def _refresh_all(self):
        self._refresh_stats()
        self._refresh_page(self._page)

    def _refresh_page(self, page):
        {
            "dashboard":  self._r_dashboard,
            "threats":    self._r_threats,
            "quarantine": self._r_quarantine,
            "shields":    self._r_shields,
            "email_mgr":  self._refresh_email_mgr,
            "blocklist":  self._r_blocklist,
            "dns_block":  self._r_dns_block,
            "settings":   self._r_settings,
            "extension": lambda: None,
            "community":  self._r_community,
            "submissions": self._r_submissions,
        }.get(page, lambda: None)()

    def _refresh_stats(self):
        threats = self.storage.threat_log
        today = time.strftime("%Y-%m-%d")
        tn = sum(1 for t in threats if self._tdate(t) == today)
        active = self.storage.config.get("active_shields", [])
        up = int(time.time()-self._start)

        self._s["total"].configure(text=str(len(threats)))
        self._s["today"].configure(text=str(tn))
        self._s["uptime"].configure(text=self._fmt_up(up))
        self._s["shields"].configure(text=f"{len(active)}/3")

        self._nav_btns["threats"].configure(
            text=f"  ◈   Threat Log [{tn}]" if tn else "  ◈   Threat Log")

        for k, lbl in self._pills.items():
            on = k in active
            lbl.configure(text="● ON" if on else "○ OFF",
                          text_color=TEAL2 if on else TEXT3)

        try:
            from app.launcher import is_registered_startup
            on = is_registered_startup()
            self._startup_sw.select() if on else self._startup_sw.deselect()
            if hasattr(self, "_set_sw"):
                self._set_sw.select() if on else self._set_sw.deselect()
        except Exception:
            pass

    def _r_dashboard(self):
        self._render_threats(
            self._dash_list,
            list(reversed(self.storage.threat_log[-20:])),
            clickable=False)

    def _r_threats(self):
        threats = list(reversed(self.storage.threat_log))
        if self._filter != "all":
            threats = [t for t in threats
                       if t.get("shield") == self._filter]
        self._render_threats(self._threat_scroll, threats[:150],
                             clickable=True)

    def _render_threats(self, container, threats, clickable=False):
        for w in container.winfo_children():
            w.destroy()
        if not threats:
            ctk.CTkLabel(container,
                         text="No threats detected yet.\nAll shields active.",
                         font=F(13), text_color=TEXT3,
                         justify="center").pack(pady=32)
            return
        hdr = ctk.CTkFrame(container, fg_color=BG3, corner_radius=6)
        hdr.pack(fill="x", pady=(0, 4))
        for lbl, w in [("TIME", 86), ("SHIELD", 80),
                       ("THREAT", 0), ("SCORE", 50)]:
            ctk.CTkLabel(hdr, text=lbl, font=M(9),
                         text_color=TEXT3, width=w).pack(
                             side="left", padx=8, pady=7)
        for i, t in enumerate(threats):
            row_bg = BG2 if i % 2 == 0 else BG3
            row = ctk.CTkFrame(container, fg_color=row_bg, corner_radius=4)
            row.pack(fill="x", pady=1)

            ts = self._ttime(t)
            sh = t.get("shield", "?").upper()
            subj = (t.get("subject") or t.get("url") or
                    t.get("file") or t.get("type", "Unknown"))[:65]
            sc = int((t.get("score") or 0)*100)
            sc_c = RED if sc >= 70 else AMBER if sc >= 40 else TEAL2
            sh_c = {"EMAIL": BLUE, "WEB": AMBER,
                    "ENDPOINT": TEAL2}.get(sh, TEXT3)

            ctk.CTkLabel(row, text=ts, font=M(10),
                         text_color=TEXT3, width=86).pack(
                             side="left", padx=(12, 4), pady=6)
            bf = ctk.CTkFrame(row, fg_color=BG4, corner_radius=4, width=76)
            bf.pack(side="left", padx=(0, 6), pady=4)
            bf.pack_propagate(False)
            ctk.CTkLabel(bf, text=sh, font=M(9),
                         text_color=sh_c).pack(fill="both", expand=True)
            ctk.CTkLabel(row, text=subj, font=F(12),
                         text_color=TEXT, anchor="w").pack(
                             side="left", fill="x", expand=True, padx=(0, 6))
            ctk.CTkLabel(row, text=str(sc) if sc else "—",
                         font=M(11, True), text_color=sc_c,
                         width=48).pack(side="right", padx=(0, 12))

            if clickable:
                # bind only on row — no child iteration (causes lag)
                row.configure(cursor="hand2")
                row.bind("<Button-1>",
                         lambda e, threat=t: self._show_threat_detail(threat))

    def _show_threat_detail(self, t: dict):
        """Show detailed threat info in right panel — no CTkScrollableFrame."""
        for w in self._detail_panel.winfo_children():
            w.destroy()

        # plain frame avoids CTkScrollableFrame font init crash
        outer = ctk.CTkFrame(self._detail_panel,
                             fg_color=BG2, corner_radius=0)
        outer.pack(fill="both", expand=True)

        shield = t.get("shield", "?").upper()
        sh_c = {"EMAIL": BLUE, "WEB": AMBER,
                "ENDPOINT": TEAL2}.get(shield, TEXT3)
        score = int((t.get("score") or 0) * 100)
        sc_c = RED if score >= 70 else AMBER if score >= 40 else TEAL2
        action = t.get("action", "logged")

        ACTION_MAP = {
            "quarantine":      (TEAL2, "🔒 Quarantined"),
            "file_quarantined": (TEAL2, "🔒 Quarantined"),
            "delete":          (RED,   "🗑 Deleted from disk"),
            "file_deleted":    (RED,   "🗑 Deleted from disk"),
            "allowed_by_user": (AMBER, "✓ Allowed by user"),
            "file_allowed":    (AMBER, "✓ Allowed by user"),
            "sandboxed":       (BLUE,  "🔬 Sandboxed"),
            "sandbox":         (BLUE,  "🔬 Sandboxed"),
            "block":           (RED,   "⊘ Blocked"),
            "dns_blocked":     (RED,   "⊘ DNS Blocked"),
            "blocked":         (RED,   "⊘ Blocked by shield"),
            "dismiss":         (TEXT3, "✕ Dismissed"),
            "mark_safe":       (TEAL2, "✓ Marked safe"),
            "posted":          (TEAL2, "📤 Posted to Community"),
            "logged":          (TEXT3, "◈ Logged — no action"),
            "":                (TEXT3, "◈ Logged — no action"),
        }
        ac, al = ACTION_MAP.get(action, (TEXT3, action.title()))

        # header strip
        hdr = ctk.CTkFrame(outer, fg_color=BG3, corner_radius=0)
        hdr.pack(fill="x")
        ctk.CTkLabel(hdr, text="Threat Details",
                     font=M(10), text_color=TEXT3).pack(
                         anchor="w", padx=14, pady=(10, 4))
        ctk.CTkFrame(outer, fg_color=BORD, height=1,
                     corner_radius=0).pack(fill="x")

        def drow(label, value, color=TEXT2):
            f = ctk.CTkFrame(outer, fg_color=BG2)
            f.pack(fill="x", padx=14, pady=2)
            ctk.CTkLabel(f, text=label, font=M(9),
                         text_color=TEXT3, width=72,
                         anchor="w").pack(side="left")
            ctk.CTkLabel(f, text=str(value)[:55],
                         font=F(11), text_color=color,
                         anchor="w").pack(
                             side="left", fill="x", expand=True)

        drow("Time",   self._ttime(t))
        drow("Shield", shield, sh_c)
        drow("Score",  f"{score}/100", sc_c)

        subj = (t.get("subject") or t.get("url") or
                t.get("file") or t.get("type", ""))
        if subj:
            drow("Threat", subj[:50], AMBER)
        if t.get("sender"):
            drow("From",   t["sender"][:45])
        if t.get("url"):
            drow("URL",    t["url"][:45])
        if t.get("file"):
            drow("File",   t["file"][:45])
        if t.get("sha256"):
            drow("Hash",   t["sha256"][:22] + "...")
        if t.get("source"):
            drow("Source", t["source"].replace("_", " ").title())

        # action taken
        ctk.CTkFrame(outer, fg_color=BORD, height=1,
                     corner_radius=0).pack(fill="x", pady=(6, 0))
        af = ctk.CTkFrame(outer, fg_color=BG3, corner_radius=6)
        af.pack(fill="x", padx=14, pady=6)
        ctk.CTkLabel(af, text="ACTION TAKEN",
                     font=M(9), text_color=TEXT3).pack(
                         anchor="w", padx=10, pady=(6, 2))
        ctk.CTkLabel(af, text=al, font=F(12, True),
                     text_color=ac).pack(anchor="w", padx=10, pady=(0, 6))

        # if sandboxed — show post-sandbox action buttons
        if action == "sandboxed":
            ctk.CTkLabel(outer, text="POST-SANDBOX ACTIONS",
                         font=M(9), text_color=TEXT3).pack(
                             anchor="w", padx=14, pady=(8, 4))
            sb_row = ctk.CTkFrame(outer, fg_color=BG2)
            sb_row.pack(fill="x", padx=14, pady=(0, 6))

            sha256 = t.get("sha256", "")
            fpath = t.get("path", "") or t.get("file", "")

            def _quarantine_after_sandbox():
                if sha256:
                    self.storage.update_learned("malicious_hashes", sha256)
                t["action"] = "quarantine"
                self.storage.save("threat_log.json",
                                  self.storage.threat_log)
                # try to delete actual file if path known
                import pathlib
                try:
                    fp = pathlib.Path(str(fpath))
                    if fp.exists():
                        fp.unlink()
                except Exception:
                    pass
                self._show_threat_detail(t)

            def _delete_after_sandbox():
                import pathlib
                try:
                    fp = pathlib.Path(str(fpath))
                    if fp.exists():
                        fp.unlink()
                except Exception:
                    pass
                if sha256:
                    self.storage.update_learned("malicious_hashes", sha256)
                t["action"] = "quarantine"
                self.storage.save("threat_log.json",
                                  self.storage.threat_log)
                self._show_threat_detail(t)

            def _safe_after_sandbox():
                if sha256:
                    self.storage.update_learned("safe_hashes", sha256)
                t["action"] = "allowed_by_user"
                self.storage.save("threat_log.json",
                                  self.storage.threat_log)
                self._show_threat_detail(t)

            ctk.CTkButton(sb_row,
                          text="🔒 Quarantine",
                          font=F(10), height=28, width=100,
                          fg_color="#1a0808", text_color=RED,
                          hover_color="#2a0a0a", corner_radius=4,
                          command=_quarantine_after_sandbox).pack(
                              side="left", padx=(0, 5))
            ctk.CTkButton(sb_row,
                          text="🗑 Delete File",
                          font=F(10), height=28, width=90,
                          fg_color="#1a0f00", text_color=AMBER,
                          hover_color="#2a1a00", corner_radius=4,
                          command=_delete_after_sandbox).pack(
                              side="left", padx=(0, 5))
            ctk.CTkButton(sb_row,
                          text="✓ Mark Safe",
                          font=F(10), height=28, width=85,
                          fg_color=BG3, text_color=TEAL2,
                          hover_color=BG4, corner_radius=4,
                          command=_safe_after_sandbox).pack(side="left")

        # if no action taken yet — show shield-appropriate action buttons
        if action in ("logged", ""):
            ctk.CTkLabel(outer, text="TAKE ACTION",
                         font=M(9), text_color=TEXT3).pack(
                             anchor="w", padx=14, pady=(8, 4))
            btn_row = ctk.CTkFrame(outer, fg_color=BG2)
            btn_row.pack(fill="x", padx=14, pady=(0, 6))

            sha256 = t.get("sha256", "")
            url = t.get("url", "")
            sender = t.get("sender", "")
            shield_t = t.get("shield", "").lower()

            def _save_action(act):
                t["action"] = act
                self.storage.save("threat_log.json", self.storage.threat_log)
                self._show_threat_detail(t)

            if shield_t == "web":
                # Web threats: block domain or mark safe — no hash quarantine
                from urllib.parse import urlparse
                try:
                    domain = urlparse(url).netloc.lstrip("www.") if url else ""
                except Exception:
                    domain = ""

                def _block_domain():
                    if domain:
                        p = self.storage.learned_patterns
                        bl = p.get("blocked_senders", [])
                        if domain not in bl:
                            bl.append(domain)
                            p["blocked_senders"] = bl
                            self.storage.save("learned_patterns.json", p)
                    _save_action("block")

                def _allow_url():
                    if url:
                        self.storage.cache_url(url, True)
                    _save_action("allowed_by_user")

                ctk.CTkButton(btn_row,
                              text="⊘ Block Domain",
                              font=F(10), height=26, width=130,
                              fg_color="#1a0808", text_color=RED,
                              hover_color="#2a0a0a", corner_radius=4,
                              command=_block_domain).pack(
                                  side="left", padx=(0, 6))
                ctk.CTkButton(btn_row,
                              text="✓ Allow URL",
                              font=F(10), height=26, width=100,
                              fg_color=BG3, text_color=TEAL2,
                              hover_color=BG4, corner_radius=4,
                              command=_allow_url).pack(side="left")

            elif shield_t == "email":
                # Email threats: block sender or mark safe
                def _block_sender():
                    if sender:
                        import re
                        m = re.search(r'<(.+?)>', sender)
                        addr = m.group(1) if m else sender
                        p = self.storage.learned_patterns
                        bl = p.get("blocked_senders", [])
                        if addr not in bl:
                            bl.append(addr)
                            p["blocked_senders"] = bl
                            self.storage.save("learned_patterns.json", p)
                    _save_action("block")

                def _mark_safe_email():
                    if sender:
                        import re
                        m = re.search(r'<(.+?)>', sender)
                        addr = m.group(1) if m else sender
                        sl = self.storage.learned_patterns.get(
                            "safe_senders", [])
                        if addr not in sl:
                            sl.append(addr)
                            self.storage.learned_patterns["safe_senders"] = sl
                            self.storage.save("learned_patterns.json",
                                              self.storage.learned_patterns)
                    _save_action("mark_safe")

                ctk.CTkButton(btn_row,
                              text="⊘ Block Sender",
                              font=F(10), height=26, width=120,
                              fg_color="#1a0808", text_color=RED,
                              hover_color="#2a0a0a", corner_radius=4,
                              command=_block_sender).pack(
                                  side="left", padx=(0, 6))
                ctk.CTkButton(btn_row,
                              text="✓ Mark Safe",
                              font=F(10), height=26, width=100,
                              fg_color=BG3, text_color=TEAL2,
                              hover_color=BG4, corner_radius=4,
                              command=_mark_safe_email).pack(side="left")

            else:
                # Endpoint threats: quarantine hash or allow
                def _quarantine_from_log():
                    if sha256:
                        self.storage.update_learned("malicious_hashes", sha256)
                    _save_action("quarantine")

                def _allow_from_log():
                    if sha256:
                        self.storage.update_learned("safe_hashes", sha256)
                    _save_action("allowed_by_user")

                ctk.CTkButton(btn_row,
                              text="🔒 Quarantine Hash",
                              font=F(10), height=26, width=130,
                              fg_color="#1a0808", text_color=RED,
                              hover_color="#2a0a0a", corner_radius=4,
                              command=_quarantine_from_log).pack(
                                  side="left", padx=(0, 6))
                ctk.CTkButton(btn_row,
                              text="✓ Mark Safe",
                              font=F(10), height=26, width=100,
                              fg_color=BG3, text_color=TEAL2,
                              hover_color=BG4, corner_radius=4,
                              command=_allow_from_log).pack(side="left")

        # post to community button
        ctk.CTkFrame(outer, fg_color=BORD, height=1,
                     corner_radius=0).pack(fill="x", pady=(6, 0))
        post_row = ctk.CTkFrame(outer, fg_color=BG2)
        post_row.pack(fill="x", padx=14, pady=6)
        ctk.CTkLabel(post_row, text="COMMUNITY",
                     font=M(9), text_color=TEXT3,
                     anchor="w").pack(anchor="w", pady=(0, 4))

        def _post_to_community():
            try:
                from utils.community_reporter import CommunityReporter
                cr = CommunityReporter(self.storage)
                result = cr.manual_report(t)
                if result.get("ok"):
                    t["community_posted"] = True
                    self.storage.save("threat_log.json",
                                      self.storage.threat_log)
                    msg1 = "✓ Threat shared with community\n\n" + \
                        result.get("message", "Submitted")
                    messagebox.showinfo("Posted", msg1)
                    self._show_threat_detail(t)
                else:
                    err_msg = result.get("message", "Submission failed") + \
                        "\n\nEnable community reporting and add URLhaus API key in Settings."
                    messagebox.showerror("Not Submitted", err_msg)
            except Exception as e:
                messagebox.showerror("Error", str(e))

        already_posted = t.get("community_posted", False)
        ctk.CTkButton(post_row,
                      text="✓ Already Shared" if already_posted
                      else "📤 Post to Community",
                      font=F(10), height=28,
                      fg_color=BG3 if already_posted else TEAL3,
                      text_color=TEAL2,
                      hover_color=BG4 if already_posted else TEAL,
                      corner_radius=4,
                      state="disabled" if already_posted else "normal",
                      command=_post_to_community).pack(
                          side="left", padx=(0, 6))
        ctk.CTkLabel(post_row,
                     text="Share this threat with URLhaus & ThreatFox",
                     font=F(9), text_color=TEXT3,
                     anchor="w").pack(side="left")

        # signals
        signals = (t.get("signals") or t.get("reasons") or
                   t.get("indicators") or [])
        if signals:
            ctk.CTkLabel(outer, text="DETECTION SIGNALS",
                         font=M(9), text_color=TEXT3).pack(
                             anchor="w", padx=14, pady=(8, 4))
            for sig in signals[:10]:
                ctk.CTkLabel(outer,
                             text=f"  → {str(sig)[:60]}",
                             font=M(9), text_color=TEXT2,
                             anchor="w").pack(
                                 fill="x", padx=14, pady=1)

        # AI analysis if present
        ai_text = t.get("ai_analysis", "")
        if ai_text:
            ctk.CTkLabel(outer, text="AI ANALYSIS",
                         font=M(9), text_color=TEXT3).pack(
                             anchor="w", padx=14, pady=(8, 4))
            ctk.CTkLabel(outer,
                         text=ai_text[:300],
                         font=F(10), text_color=TEXT2,
                         wraplength=240,
                         justify="left", anchor="w").pack(
                             fill="x", padx=14, pady=(0, 8))

    def _r_quarantine(self):
        for w in self._q_scroll.winfo_children():
            w.destroy()
        q = BASE_DIR/"data"/"quarantine"
        files = (sorted(q.iterdir(), key=lambda f: f.stat().st_mtime,
                        reverse=True) if q.exists() else [])
        if not files:
            ctk.CTkLabel(self._q_scroll, text="Quarantine is empty",
                         font=F(13), text_color=TEXT3).pack(pady=32)
            return
        ctk.CTkLabel(self._q_scroll, text=f"{len(files)} file(s)",
                     font=M(10), text_color=TEXT3, anchor="w").pack(
                         anchor="w", padx=14, pady=(10, 6))
        for f in files[:50]:
            row = ctk.CTkFrame(self._q_scroll, fg_color=BG3, corner_radius=6)
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text="⚠", font=("", 14),
                         text_color=RED, width=34).pack(
                             side="left", padx=(8, 0), pady=9)
            ctk.CTkLabel(row, text=f.name[:60], font=M(11),
                         text_color=TEXT, anchor="w").pack(
                             side="left", fill="x", expand=True, padx=8)
            ctk.CTkLabel(row, text=self._fmt_sz(f.stat().st_size),
                         font=M(9), text_color=TEXT3, width=68).pack(
                             side="right", padx=4)
            ctk.CTkButton(row, text="Delete", font=F(11),
                          width=60, height=24, fg_color=BG4,
                          text_color=RED, hover_color="#2a0808",
                          corner_radius=4,
                          command=lambda fp=f: self._del_q(fp)
                          ).pack(side="right", padx=(0, 8))

    def _r_shields(self):
        active = self.storage.config.get("active_shields", [])
        for k, sw in self._shield_sw.items():
            on = k in active
            sw.select() if on else sw.deselect()
            self._shield_lbl[k].configure(
                text="ACTIVE" if on else "DISABLED",
                text_color=TEAL2 if on else TEXT3)

    def _r_blocklist(self):
        for w in self._bl_scroll.winfo_children():
            w.destroy()
        blocked = self.storage.learned_patterns.get("blocked_senders", [])
        if not blocked:
            ctk.CTkLabel(self._bl_scroll,
                         text="Block list is empty",
                         font=F(13), text_color=TEXT3).pack(pady=32)
            return
        ctk.CTkLabel(self._bl_scroll,
                     text=f"{len(blocked)} entries — email senders and web domains",
                     font=M(10), text_color=TEXT3, anchor="w").pack(
                         anchor="w", padx=14, pady=(10, 6))
        for entry in blocked:
            row = ctk.CTkFrame(self._bl_scroll, fg_color=BG3, corner_radius=6)
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text="⊘", font=("", 13),
                         text_color=RED, width=34).pack(
                             side="left", padx=(8, 0), pady=9)
            ctk.CTkLabel(row, text=entry, font=M(12),
                         text_color=TEXT, anchor="w").pack(
                             side="left", fill="x", expand=True, padx=8)
            ctk.CTkButton(row, text="Unblock", font=F(11),
                          width=74, height=26, fg_color=BG4,
                          text_color=TEAL2, hover_color=TEAL3,
                          corner_radius=4,
                          command=lambda e=entry: self._unblock(e)
                          ).pack(side="right", padx=(0, 8))

    def _r_dns_block(self):
        for w in self._dns_scroll.winfo_children():
            w.destroy()
        # DNS blocked domains are in url_cache with blocked=True
        # and also in learned_patterns blocked_senders (IP-based)
        url_cache = self.storage.url_cache
        dns_blocked = [
            url for url, data in url_cache.items()
            if isinstance(data, dict) and not data.get("safe", True)
        ]
        # also get IPs from blocked_senders that look like IPs
        import re
        all_blocked = self.storage.learned_patterns.get("blocked_senders", [])
        ip_blocked = [b for b in all_blocked
                      if re.match(r'^\d+\.\d+\.\d+\.\d+$', b)]
        combined = list(set(dns_blocked + ip_blocked))

        if not combined:
            ctk.CTkLabel(self._dns_scroll,
                         text="No DNS blocks yet.\nDNS blocking activates when you block a domain via the Web Shield.",
                         font=F(13), text_color=TEXT3,
                         justify="center").pack(pady=32)
            return
        ctk.CTkLabel(self._dns_scroll,
                     text=f"{len(combined)} domains/IPs blocked at DNS level",
                     font=M(10), text_color=TEXT3, anchor="w").pack(
                         anchor="w", padx=14, pady=(10, 6))
        for entry in combined[:100]:
            row = ctk.CTkFrame(self._dns_scroll, fg_color=BG3, corner_radius=6)
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text="◌", font=("", 13),
                         text_color=AMBER, width=34).pack(
                             side="left", padx=(8, 0), pady=9)
            ctk.CTkLabel(row, text=entry[:70], font=M(11),
                         text_color=TEXT, anchor="w").pack(
                             side="left", fill="x", expand=True, padx=8)
            ctk.CTkButton(row, text="Remove", font=F(11),
                          width=70, height=26, fg_color=BG4,
                          text_color=TEAL2, hover_color=TEAL3,
                          corner_radius=4,
                          command=lambda e=entry: self._remove_dns_block(e)
                          ).pack(side="right", padx=(0, 8))

    def _r_settings(self):
        import platform as _p
        self._sys_info.configure(
            text=(f"Platform   {_p.system()} {_p.release()}\n"
                  f"Python     {_p.python_version()}\n"
                  f"Threats    {len(self.storage.threat_log)} logged\n"
                  f"Uptime     {self._fmt_up(int(time.time()-self._start))}"))
        try:
            on = self.storage.config.get("community_reporting", False)
            self._comm_sw.select() if on else self._comm_sw.deselect()
        except Exception:
            pass

    # ── actions ───────────────────────────────────────────────────────────
    def _set_filter(self, val):
        self._filter = val
        for v, b in self._filter_btns.items():
            b.configure(fg_color=TEAL if v == val else BG3,
                        text_color=TEXT if v == val else TEXT2)
        self._r_threats()

    def _toggle_shield(self, key):
        active = list(self.storage.config.get("active_shields", []))
        if key in active:
            active.remove(key)
        else:
            active.append(key)
        self.storage.config["active_shields"] = active
        self.storage.save("config.json", self.storage.config)
        self._r_shields()
        self._refresh_stats()

    def _toggle_startup(self):
        try:
            from app.launcher import (is_registered_startup,
                                      register_startup,
                                      unregister_startup)
            if is_registered_startup():
                unregister_startup()
            else:
                register_startup()
            self._refresh_stats()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _toggle_community(self):
        cur = self.storage.config.get("community_reporting", False)
        self.storage.config["community_reporting"] = not cur
        self.storage.save("config.json", self.storage.config)

    def _save_vt_key(self):
        key = self._vt_entry.get().strip()
        self.storage.config["virustotal_api_key"] = key
        self.storage.save("config.json", self.storage.config)
        messagebox.showinfo("Saved", "VirusTotal API key saved.")

    def _unblock(self, entry):
        if not messagebox.askyesno("Unblock",
                                   f"Remove '{entry}' from block list?"):
            return
        p = self.storage.learned_patterns
        p["blocked_senders"] = [b for b in
                                p.get("blocked_senders", [])
                                if b != entry]
        self.storage.save("learned_patterns.json", p)
        cache = {k: v for k, v in self.storage.url_cache.items()
                 if entry not in k}
        self.storage.save("url_cache.json", cache)
        self._r_blocklist()

    def _remove_dns_block(self, entry):
        if not messagebox.askyesno("Remove",
                                   f"Remove DNS block for '{entry}'?"):
            return
        # remove from url_cache
        cache = {k: v for k, v in self.storage.url_cache.items()
                 if entry not in k}
        self.storage.save("url_cache.json", cache)
        # also remove from blocked_senders if it's an IP
        p = self.storage.learned_patterns
        p["blocked_senders"] = [b for b in
                                p.get("blocked_senders", [])
                                if b != entry]
        self.storage.save("learned_patterns.json", p)
        self._r_dns_block()

    def _del_q(self, path):
        if not messagebox.askyesno("Delete",
                                   f"Permanently delete '{path.name}'?"):
            return
        try:
            path.unlink()
            self._r_quarantine()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _open_data(self):
        d = BASE_DIR/"data"
        if IS_WIN:
            os.startfile(str(d))
        else:
            subprocess.Popen(["xdg-open", str(d)])

    def _open_url(self, url):
        import webbrowser
        webbrowser.open(url)

    def _tick(self):
        self._clock.configure(
            text=time.strftime("  %H:%M:%S  —  %d %b"))

    def _tdate(self, t):
        ts = t.get("timestamp", "")
        if isinstance(ts, float):
            return time.strftime("%Y-%m-%d", time.localtime(ts))
        return str(ts)[:10]

    def _ttime(self, t):
        ts = t.get("timestamp", "")
        if isinstance(ts, float):
            return time.strftime("%H:%M:%S", time.localtime(ts))
        s = str(ts)
        return s[11:19] if len(s) > 11 else s[:8]

    def _fmt_up(self, s):
        if s < 60:
            return f"{s}s"
        if s < 3600:
            return f"{s//60}m {s % 60}s"
        return f"{s//3600}h {(s % 3600)//60}m"

    def _fmt_sz(self, b):
        if b < 1024:
            return f"{b}B"
        if b < 1048576:
            return f"{b/1024:.1f}KB"
        return f"{b/1048576:.1f}MB"


def launch_app(storage, daemon=None):
    app = ThreatShieldApp(storage)
    app.mainloop()

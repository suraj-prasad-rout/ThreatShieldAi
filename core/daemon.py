"""
ThreatShield AI — Main Daemon
Merged: all old shield/server methods preserved
      + new: show_ui param, hide-on-close, background mode, tray keeps running
"""
import sys
import os
import time
import threading
from pathlib import Path
from core.event_bus import EventBus
from core.storage import Storage
from core.logger import get_logger

log = get_logger("daemon")

# ── single shared storage instance ───────────────────────────────────────────
_shared_storage = None
_shared_daemon = None


def get_shared_storage() -> Storage:
    global _shared_storage
    if _shared_storage is None:
        _shared_storage = Storage()
    return _shared_storage


def get_shared_daemon():
    return _shared_daemon


class ThreatShieldDaemon:
    def __init__(self):
        global _shared_daemon
        self.storage = get_shared_storage()
        self.bus = EventBus()
        self._shields = {}
        self._threat_count = 0
        self._tray = None
        self._ui_window = None
        self._ui_lock = threading.Lock()
        self._running = True
        _shared_daemon = self
        self.bus.on("threat_found", self._on_threat)

    # ── threat handler ────────────────────────────────────────────────────
    def _on_threat(self, payload):
        self._threat_count += 1
        shield = payload.get("shield", "?") if payload else "?"
        msg = (payload.get("subject") or payload.get("url") or
               payload.get("file") or "threat") if payload else "threat"
        log.warning(f"THREAT #{self._threat_count} [{shield}] {msg}")
        try:
            from utils.notifier import notify
            notify("ThreatShield AI",
                   f"[{shield.upper()}] {str(msg)[:60]}")
        except Exception:
            pass
        if self._tray:
            try:
                self._tray.title = (
                    f"ThreatShield AI — "
                    f"{self._threat_count} threats blocked")
            except Exception:
                pass

    # ── shield loading ────────────────────────────────────────────────────
    def _load_shield(self, name: str):
        if name in self._shields:
            return self._shields[name]
        try:
            if name == "email":
                from shields.email.email_shield import EmailShield
                self._shields["email"] = EmailShield(
                    self.storage, self.bus)
            elif name == "web":
                from shields.web.web_shield import WebShield
                self._shields["web"] = WebShield(
                    self.storage, self.bus)
            elif name == "endpoint":
                from shields.endpoint.endpoint_shield import EndpointShield
                self._shields["endpoint"] = EndpointShield(
                    self.storage, self.bus)
            log.info(f"Shield loaded: {name}")
        except Exception as e:
            log.error(f"Failed to load shield {name}: {e}")
        return self._shields.get(name)

    def _start_shield(self, name: str):
        shield = self._load_shield(name)
        if shield:
            t = threading.Thread(
                target=shield.start, daemon=True,
                name=f"shield-{name}")
            t.start()

    # ── servers ───────────────────────────────────────────────────────────
    # kept both old names (_start_web_server / _start_dns_servers)
    # plus new combined name (_start_web_servers) — all work
    def _start_web_server(self):
        try:
            from shields.web.web_server import start_server
            web_shield = self._load_shield("web")
            if web_shield:
                start_server(self.storage, web_shield)
        except Exception as e:
            log.error(f"Web server failed: {e}")

    def _start_dns_servers(self):
        try:
            from shields.web.block_page_server import start_block_page_server
            start_block_page_server(self.storage)
        except Exception as e:
            log.warning(f"Block page server: {e}")
        try:
            from shields.web.dns_server import (
                start_dns_server, configure_windows_dns)
            ok = start_dns_server(self.storage)
            if ok:
                configure_windows_dns(enable=True)
        except Exception as e:
            log.warning(f"DNS server: {e}")

    # alias so new code calling _start_web_servers also works
    def _start_web_servers(self):
        self._start_web_server()
        self._start_dns_servers()

    def _start_learner(self):
        try:
            from models.learner import LocalLearner
            LocalLearner(self.storage).start_background_loop(
                interval_seconds=300)
            log.info("Local AI learning loop started")
        except Exception as e:
            log.warning(f"Learner not started: {e}")

    def _start_community_reporter(self):
        try:
            from utils.community_reporter import CommunityReporter
            CommunityReporter(self.storage).start_background_sync(
                interval_hours=6)
            log.info("Community threat reporting active")
        except Exception as e:
            log.warning(f"Community reporter: {e}")

    # ── tray icon ─────────────────────────────────────────────────────────
    def _make_tray_icon(self):
        try:
            import pystray
            from PIL import Image, ImageDraw
            size = 64
            img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
            d = ImageDraw.Draw(img)
            d.polygon(
                [(32, 4), (58, 14), (58, 36), (32, 60), (6, 36), (6, 14)],
                fill=(29, 158, 117))
            d.polygon(
                [(32, 10), (52, 18), (52, 36), (32, 55), (12, 36), (12, 18)],
                fill=(15, 110, 86, 120))

            def _open(icon, item):
                # show UI — create new or bring existing to front
                threading.Thread(
                    target=self._show_ui, daemon=True).start()

            def _quit(icon, item):
                log.info("User quit ThreatShield via tray")
                self._running = False
                icon.stop()
                os._exit(0)

            menu = pystray.Menu(
                pystray.MenuItem("ThreatShield AI", None, enabled=False),
                pystray.MenuItem(
                    lambda _: f"{self._threat_count} threats blocked",
                    None, enabled=False),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Open Dashboard", _open, default=True),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Quit ThreatShield", _quit),
            )
            self._tray = pystray.Icon(
                "ThreatShield", img,
                "ThreatShield AI — Protecting your system",
                menu)
            return self._tray
        except Exception as e:
            log.warning(f"Tray not available: {e}")
            return None

    # ── UI management ─────────────────────────────────────────────────────
    def _show_ui(self):
        """
        Called by: tray icon, _signal_existing_instance, or direct launch.
        - If window exists and visible  → bring to front
        - If window exists but hidden   → show it again
        - If no window                  → create new one
        """
        with self._ui_lock:
            if self._ui_window is not None:
                try:
                    self._ui_window.deiconify()
                    self._ui_window.lift()
                    self._ui_window.focus_force()
                    return
                except Exception:
                    self._ui_window = None

        # must run on main thread — use after() if called from thread
        try:
            self._launch_ui_window()
        except Exception as e:
            log.error(f"UI launch error: {e}")

    def _launch_ui_window(self):
        """
        Create UI window. X button HIDES it (withdraw), never destroys.
        Shields continue running when window is hidden.
        """
        from ui.app import ThreatShieldApp

        app = ThreatShieldApp(self.storage)

        # X button: hide window, keep daemon running
        def _on_close():
            app.withdraw()
            log.info("UI hidden — all shields still active in background")

        app.protocol("WM_DELETE_WINDOW", _on_close)

        with self._ui_lock:
            self._ui_window = app

        log.info("UI window opened")
        app.mainloop()  # blocks until app.quit() is called

        with self._ui_lock:
            self._ui_window = None
        log.info("UI window destroyed")

    # ── OLD _show_ui for backward compat (called by old code) ─────────────
    # Old code: self._show_ui() → launch_app(storage, self)
    # This is now handled by _launch_ui_window above.
    # Keeping this alias so any code that calls launch_app still works.
    def _show_ui_compat(self):
        try:
            from ui.app import launch_app
            launch_app(self.storage, self)
        except Exception as e:
            log.error(f"UI launch error: {e}")

    # ── main run ──────────────────────────────────────────────────────────
    def run(self, show_ui: bool = True):
        """
        show_ui=True  → start shields + show UI window (normal launch)
        show_ui=False → start shields silently, tray only (--background)

        Fully backward compatible:
          Old style: daemon.run()        → show_ui defaults to True ✓
          New style: daemon.run(show_ui=False) → background mode ✓
        """
        log.info("ThreatShield AI starting up")

        # start all active shields
        for name in self.storage.config.get(
                "active_shields", ["email", "web", "endpoint"]):
            self._start_shield(name)

        # start servers (uses old method names — both work)
        self._start_web_server()
        self._start_dns_servers()

        # start background services
        self._start_community_reporter()
        self._start_learner()

        log.info("All shields active")

        # tray icon always runs in background thread
        tray = self._make_tray_icon()
        if tray:
            threading.Thread(
                target=tray.run, daemon=True, name="tray").start()
            log.info("System tray icon active")

        if show_ui:
            # UI runs on main thread — blocks here until window is closed
            self._launch_ui_window()
        else:
            # Background mode: keep process alive, no window
            log.info(
                "Running in background — "
                "click tray icon to open dashboard")
            try:
                while self._running:
                    time.sleep(1)
            except KeyboardInterrupt:
                log.info("ThreatShield stopped by user (Ctrl+C)")

        log.info("ThreatShield stopped")

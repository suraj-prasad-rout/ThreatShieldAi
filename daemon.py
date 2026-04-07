"""
ThreatShield AI — main daemon
Starts silently on boot, lives in system tray.
Lazy-loads each shield only when its trigger fires.
"""
import threading
import pystray
from PIL import Image, ImageDraw
from core.event_bus import EventBus
from core.storage import Storage
from core.logger import get_logger

log = get_logger("daemon")


class ThreatShieldDaemon:
    def __init__(self):
        self.storage = Storage()
        self.bus = EventBus()
        self._shields = {}          # loaded on demand

    # ── shield lazy-loading ──────────────────────────────────────────────
    def _load_shield(self, name: str):
        if name in self._shields:
            return self._shields[name]
        if name == "email":
            from shields.email.email_shield import EmailShield
            self._shields["email"] = EmailShield(self.storage, self.bus)
        elif name == "web":
            from shields.web.web_shield import WebShield
            self._shields["web"] = WebShield(self.storage, self.bus)
        elif name == "endpoint":
            from shields.endpoint.endpoint_shield import EndpointShield
            self._shields["endpoint"] = EndpointShield(self.storage, self.bus)
        log.info(f"Shield loaded: {name}")
        return self._shields[name]

    def start_shield(self, name: str):
        shield = self._load_shield(name)
        t = threading.Thread(target=shield.start, daemon=True)
        t.start()

    # ── tray icon ────────────────────────────────────────────────────────
    def _make_icon_image(self):
        img = Image.new("RGB", (64, 64), color=(30, 30, 30))
        d = ImageDraw.Draw(img)
        d.ellipse([8, 8, 56, 56], fill=(29, 158, 117))
        return img

    def _build_menu(self):
        return pystray.Menu(
            pystray.MenuItem("ThreatShield AI  active", None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Open Dashboard", lambda icon,
                             item: self.bus.emit("open_dashboard")),
            pystray.MenuItem("View Threat Log", lambda icon,
                             item: self.bus.emit("open_log")),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", self._quit),
        )

    def _quit(self, icon, item):
        icon.stop()

    def run(self):
        log.info("ThreatShield daemon starting")
        for name in self.storage.config.get("active_shields", ["email", "web", "endpoint"]):
            self.start_shield(name)

        icon = pystray.Icon(
            "ThreatShield",
            self._make_icon_image(),
            "ThreatShield AI",
            self._build_menu(),
        )
        icon.run()

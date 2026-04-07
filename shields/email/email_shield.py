"""
ThreatShield AI — Email Shield (Final)
Fix: Dismissed and Mark Safe actions persist across restarts.
     Dismissed email UIDs saved to data/dismissed_emails.json
     On startup, dismissed UIDs are never re-alerted.
"""
import imaplib
import email as emaillib
import datetime
import time
import threading
import re
import json
from pathlib import Path
from core.logger import get_logger
from shields.email.phishing_detector import PhishingDetector

log = get_logger("email_shield")

DISMISSED_FILE = Path(__file__).parent.parent.parent / \
    "data" / "dismissed_emails.json"


def _load_dismissed() -> set:
    """Load dismissed email UIDs from disk."""
    try:
        if DISMISSED_FILE.exists():
            with open(DISMISSED_FILE, "r") as f:
                data = json.load(f)
            return set(data.get("dismissed", []))
    except Exception as e:
        log.debug(f"Load dismissed error: {e}")
    return set()


def _save_dismissed(dismissed: set):
    """Save dismissed email UIDs to disk."""
    try:
        DISMISSED_FILE.parent.mkdir(parents=True, exist_ok=True)
        # keep only last 1000 to prevent unbounded growth
        items = list(dismissed)[-1000:]
        with open(DISMISSED_FILE, "w") as f:
            json.dump({"dismissed": items}, f, indent=2)
    except Exception as e:
        log.debug(f"Save dismissed error: {e}")


class EmailShield:
    def __init__(self, storage, bus):
        self.storage = storage
        self.bus = bus
        self.detector = PhishingDetector(storage)
        self._running = False
        # UIDs already alerted — in-memory for current session
        self._alerted = set()
        # UIDs dismissed by user — persisted to disk across restarts
        self._dismissed = _load_dismissed()
        log.debug(
            f"Loaded {len(self._dismissed)} dismissed UIDs from disk")

    def start(self):
        accounts = self._get_all_accounts()
        if not accounts:
            log.warning("No email accounts configured")
            return

        self._running = True
        log.info(
            f"Email shield started — monitoring "
            f"{len(accounts)} account(s)")

        threads = []
        for acc in accounts:
            t = threading.Thread(
                target=self._monitor_account,
                args=(acc,),
                daemon=True,
                name=f"email-{acc['imap_user']}"
            )
            t.start()
            threads.append(t)
            log.info(f"  Monitoring: {acc['imap_user']}")

        for t in threads:
            t.join()

    def _get_all_accounts(self) -> list:
        cfg = self.storage.config
        accounts = list(cfg.get("email_accounts", []))
        if not accounts and cfg.get("imap_host"):
            accounts = [{
                "imap_host": cfg["imap_host"],
                "imap_user": cfg["imap_user"],
                "imap_pass": cfg["imap_pass"],
            }]
        return accounts

    # ── per-account monitor ───────────────────────────────────────────────────
    def _monitor_account(self, account: dict):
        user = account["imap_user"]
        scanned = set()

        if not account.get("imap_pass"):
            log.warning(f"No app password for {user} — skipping")
            return

        try:
            self._startup_scan(account, scanned)
        except Exception as e:
            log.debug(f"Startup scan error [{user}]: {e}")

        while self._running:
            try:
                self._scan_unseen(account, scanned)
            except Exception as e:
                log.error(f"Scan error [{user}]: {e}")
            time.sleep(30)

    # ── startup scan ──────────────────────────────────────────────────────────
    def _startup_scan(self, account: dict, scanned: set):
        """
        On startup: scan today's emails.
        SKIP emails that were previously dismissed or marked safe.
        Only alert on genuinely new phishing that user hasn't seen.
        """
        user = account["imap_user"]
        with imaplib.IMAP4_SSL(account["imap_host"]) as mail:
            mail.login(account["imap_user"], account["imap_pass"])
            mail.select("INBOX")
            today = datetime.date.today().strftime("%d-%b-%Y")
            _, ids = mail.search(None, "SINCE", today)

            total = 0
            alerted = 0
            skipped = 0

            for uid in ids[0].split():
                uid_str = uid.decode()
                uid_key = f"{user}::{uid_str}"
                scanned.add(uid_key)
                total += 1

                # SKIP if user already dismissed or marked safe
                if uid_key in self._dismissed:
                    skipped += 1
                    log.debug(
                        f"Skipping dismissed UID: {uid_key}")
                    continue

                # SKIP if already alerted this session
                if uid_key in self._alerted:
                    continue

                try:
                    _, data = mail.fetch(uid, "(RFC822)")
                    msg = emaillib.message_from_bytes(data[0][1])
                    result = self.detector.analyze(msg)

                    if result["is_phishing"]:
                        is_blocked = self._is_blocked(result["sender"])

                        if is_blocked:
                            log.info(
                                f"Startup silent (blocked): "
                                f"{result['sender'][:50]}")
                        else:
                            threat = self._build_threat(
                                result, user)
                            self.storage.log_threat(threat)
                            self.bus.emit("threat_found", threat)
                            self._alerted.add(uid_key)
                            self._show_alert(threat, uid_key)
                            alerted += 1
                            log.warning(
                                f"Startup phishing [{user}]: "
                                f"{result['subject'][:50]} "
                                f"score={result['score']}")

                except Exception as e:
                    log.debug(f"Startup item error: {e}")

            log.info(
                f"Startup scan [{user}]: "
                f"{total} emails, {alerted} alert(s), "
                f"{skipped} skipped (previously dismissed)")

    # ── continuous scan ───────────────────────────────────────────────────────
    def _scan_unseen(self, account: dict, scanned: set):
        """Every 30s: scan UNSEEN emails only."""
        user = account["imap_user"]
        with imaplib.IMAP4_SSL(account["imap_host"]) as mail:
            mail.login(account["imap_user"], account["imap_pass"])
            mail.select("INBOX")
            _, ids = mail.search(None, "UNSEEN")

            for uid in ids[0].split():
                uid_str = uid.decode()
                uid_key = f"{user}::{uid_str}"

                if uid_key in scanned:
                    continue
                if uid_key in self._dismissed:
                    scanned.add(uid_key)
                    continue
                scanned.add(uid_key)

                try:
                    _, data = mail.fetch(uid, "(RFC822)")
                    msg = emaillib.message_from_bytes(data[0][1])
                    result = self.detector.analyze(msg)

                    if result["is_phishing"]:
                        threat = self._build_threat(result, user)
                        self.storage.log_threat(threat)
                        self.bus.emit("threat_found", threat)

                        log.warning(
                            f"Phishing [{user}]: {result['subject']}")
                        log.warning(f"  Sender: {result['sender']}")
                        log.warning(f"  Score : {result['score']}")
                        for sig in result["signals"]:
                            log.warning(f"  - {sig}")

                        is_blocked = self._is_blocked(result["sender"])

                        if is_blocked:
                            log.info(
                                f"Silent (blocked): "
                                f"{result['sender'][:50]}")
                        elif uid_key in self._alerted:
                            log.info(
                                f"Silent (duplicate): {uid_str}")
                        else:
                            self._alerted.add(uid_key)
                            self._show_alert(threat, uid_key)

                except Exception as e:
                    log.debug(f"Scan item error [{user}]: {e}")

    # ── helpers ───────────────────────────────────────────────────────────────
    def _is_blocked(self, sender: str) -> bool:
        m = re.search(r"@([\w.\-]+)", sender)
        em = re.search(r"[\w.\-+]+@[\w.\-]+", sender)
        domain = m.group(1).lower() if m else ""
        full_email = em.group(0).lower() if em else ""
        blocked = self.storage.learned_patterns.get(
            "blocked_senders", [])
        return domain in blocked or full_email in blocked

    def _build_threat(self, result: dict, account: str) -> dict:
        return {
            "shield":  "email",
            "account": account,
            "subject": result["subject"],
            "sender":  result["sender"],
            "score":   result["score"],
            "signals": result["signals"],
            "reasons": result["signals"],
            "urls":    result["urls_found"],
        }

    def _show_alert(self, threat: dict, uid_key: str):
        try:
            from shields.email.alert_window import show_alert
            show_alert(
                email_data=threat,
                storage=self.storage,
                bus=self.bus,
                on_block_sender=lambda: self._handle_action(
                    "block", threat, uid_key),
                on_block_domain=lambda: self._handle_action(
                    "block", threat, uid_key),
                on_mark_safe=lambda: self._handle_action(
                    "mark_safe", threat, uid_key),
                on_dismiss=lambda: self._handle_action(
                    "dismiss", threat, uid_key))
        except Exception as e:
            log.error(f"Alert window error: {e}")

    def _handle_action(self, action: str, threat: dict,
                       uid_key: str):
        log.info(
            f"User action '{action}' on: "
            f"{threat.get('subject', '')[:50]}")

        sender = threat.get("sender", "")
        em = re.search(r"[\w.\-+]+@[\w.\-]+", sender)
        dm = re.search(r"@([\w.\-]+)", sender)
        full_email = em.group(0).lower() if em else ""
        domain = dm.group(1).lower() if dm else ""

        PERSONAL = {
            "gmail.com", "outlook.com", "hotmail.com",
            "yahoo.com", "icloud.com", "protonmail.com",
        }

        if action == "block":
            if domain in PERSONAL:
                if full_email:
                    self.storage.update_learned(
                        "blocked_senders", full_email)
                    log.info(f"Blocked address: {full_email}")
            else:
                if domain:
                    self.storage.update_learned(
                        "blocked_senders", domain)
                    log.info(f"Blocked domain: {domain}")

        elif action == "mark_safe":
            # mark safe: add to safe list AND dismiss this UID
            if full_email:
                self.storage.update_learned(
                    "safe_domains", full_email)
            if domain:
                self.storage.update_learned(
                    "safe_domains", domain)
            # persist dismissal so it survives restarts
            self._dismissed.add(uid_key)
            _save_dismissed(self._dismissed)
            log.info(
                f"Marked safe: {full_email or domain} "
                f"— UID {uid_key} dismissed permanently")

        elif action == "dismiss":
            # dismiss: persist UID so popup never shows again
            self._dismissed.add(uid_key)
            _save_dismissed(self._dismissed)
            log.info(
                f"Dismissed permanently: UID {uid_key}")

    def stop(self):
        self._running = False

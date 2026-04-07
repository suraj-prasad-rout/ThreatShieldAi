"""
ThreatShield AI — Email User Actions
Handles: Quarantine, Block Sender, Mark as Safe
Fixes:
  - Block specific email address, NOT entire domain for gmail/yahoo etc
  - Ask for admin elevation if DNS block fails
  - Never block gmail.com, outlook.com etc as a whole domain
"""
import imaplib
import re
import subprocess
import sys
from core.logger import get_logger
from core.storage import Storage

log = get_logger("email_actions")

# domains that should NEVER be fully blocked (would break everything)
NEVER_BLOCK_DOMAINS = {
    "gmail.com","googlemail.com","outlook.com","hotmail.com","yahoo.com",
    "icloud.com","protonmail.com","live.com","msn.com",
}


class EmailActions:
    def __init__(self, storage: Storage):
        self.storage = storage

    # ── connect helper ───────────────────────────────────────────────────────
    def _connect(self, account: dict):
        mail = imaplib.IMAP4_SSL(account["imap_host"])
        mail.login(account["imap_user"], account["imap_pass"])
        return mail

    def _get_account(self, email_addr: str) -> dict:
        accounts = self.storage.config.get("email_accounts", [])
        for a in accounts:
            if a["imap_user"].lower() == email_addr.lower():
                return a
        if self.storage.config.get("imap_host"):
            return {
                "imap_host": self.storage.config["imap_host"],
                "imap_user": self.storage.config["imap_user"],
                "imap_pass": self.storage.config["imap_pass"],
            }
        return {}

    # ── ACTION 1: Quarantine ─────────────────────────────────────────────────
    def quarantine(self, account_email: str, subject: str) -> dict:
        """Move email to ThreatShield-Quarantine IMAP folder."""
        account = self._get_account(account_email)
        if not account:
            return {"success": False, "message": "Account not found in config"}
        try:
            mail = self._connect(account)
            mail.select("INBOX")

            # search by subject
            safe_subject = subject[:50].replace('"', '')
            _, ids = mail.search(None, f'SUBJECT "{safe_subject}"')
            if not ids[0]:
                mail.logout()
                return {"success": False, "message": "Email not found in inbox — may already be moved"}

            uid = ids[0].split()[-1]
            quarantine_folder = "ThreatShield-Quarantine"

            # create folder silently
            mail.create(quarantine_folder)

            # copy then delete original
            result = mail.copy(uid, quarantine_folder)
            if result[0] == "OK":
                mail.store(uid, "+FLAGS", "\\Deleted")
                mail.expunge()
                mail.logout()
                self._log_action("quarantine", account_email, subject)
                log.info(f"Quarantined: {subject[:50]}")
                return {"success": True, "message": f"Email moved to '{quarantine_folder}' folder in your Gmail"}
            else:
                mail.logout()
                return {"success": False, "message": "Could not move email — check IMAP permissions"}

        except Exception as e:
            log.error(f"Quarantine failed: {e}")
            return {"success": False, "message": f"Quarantine failed: {str(e)}"}

    # ── ACTION 2: Block Sender ───────────────────────────────────────────────
    def block_sender(self, sender: str, account_email: str = "") -> dict:
        """
        Block the specific sender.
        - For personal domains (gmail, yahoo etc): block the FULL EMAIL ADDRESS
        - For other domains: block the DOMAIN
        - Try DNS block — if fails, ask for admin elevation
        """
        full_email = self._extract_email(sender)
        domain     = self._extract_domain(sender)

        if not domain:
            return {"success": False, "message": "Could not extract sender info"}

        messages = []

        # ── decide what to block ──────────────────────────────────────────
        if domain in NEVER_BLOCK_DOMAINS:
            # block specific email only — never block entire gmail.com!
            if full_email:
                self.storage.update_learned("blocked_senders", full_email)
                messages.append(f"Blocked email address: {full_email}")
                log.info(f"Blocked specific address: {full_email}")
            else:
                return {"success": False, "message": "Could not extract email address"}
        else:
            # block the whole domain
            self.storage.update_learned("blocked_senders", domain)
            if full_email:
                self.storage.update_learned("blocked_senders", full_email)
            messages.append(f"Blocked domain: {domain}")
            log.info(f"Blocked domain: {domain}")

            # try DNS block for non-personal domains
            dns_result = self._block_dns(domain)
            if dns_result["success"]:
                messages.append("Domain blocked at DNS level (hosts file)")
            elif dns_result["needs_admin"]:
                # ask for admin elevation
                elevated = self._request_admin_elevation(domain)
                if elevated:
                    messages.append("Domain blocked at DNS level (admin elevation granted)")
                else:
                    messages.append("DNS blocking skipped (requires Administrator — right-click ThreatShield and Run as Administrator to enable)")

        # trash existing emails from this sender
        if account_email:
            trashed = self._trash_sender_emails(full_email or domain, account_email)
            if trashed > 0:
                messages.append(f"Moved {trashed} existing email(s) to trash")

        self._log_action("block", account_email, f"Blocked: {sender}")
        return {"success": True, "message": "\n".join(messages)}

    def _block_dns(self, domain: str) -> dict:
        """Add domain to Windows hosts file."""
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        entry = f"\n127.0.0.1 {domain}  # ThreatShield-blocked\n127.0.0.1 www.{domain}  # ThreatShield-blocked\n"
        try:
            with open(hosts_path, "r") as f:
                content = f.read()
            if f"ThreatShield-blocked" in content and domain in content:
                return {"success": True, "needs_admin": False}
            with open(hosts_path, "a") as f:
                f.write(entry)
            log.info(f"DNS blocked: {domain}")
            return {"success": True, "needs_admin": False}
        except PermissionError:
            log.warning(f"DNS block needs admin rights for: {domain}")
            return {"success": False, "needs_admin": True}
        except Exception as e:
            log.warning(f"DNS block error: {e}")
            return {"success": False, "needs_admin": False}

    def _request_admin_elevation(self, domain: str) -> bool:
        """
        Ask Windows to re-run the DNS block with admin rights.
        Shows a UAC prompt to the user.
        """
        try:
            import ctypes
            # check if already admin
            if ctypes.windll.shell32.IsUserAnAdmin():
                return self._block_dns(domain)["success"]

            # build a small script to add the hosts entry
            script = (
                f'$hosts = "C:\\Windows\\System32\\drivers\\etc\\hosts";'
                f'Add-Content $hosts "`n127.0.0.1 {domain}  # ThreatShield-blocked";'
                f'Add-Content $hosts "`n127.0.0.1 www.{domain}  # ThreatShield-blocked";'
                f'Write-Host "Done"'
            )
            # launch PowerShell as admin with UAC prompt
            result = subprocess.run(
                ["powershell", "-Command",
                 f'Start-Process powershell -Verb RunAs -ArgumentList \'-Command {script}\' -Wait'],
                capture_output=True, timeout=30
            )
            if result.returncode == 0:
                log.info(f"DNS blocked via admin elevation: {domain}")
                return True
            return False
        except Exception as e:
            log.warning(f"Admin elevation failed: {e}")
            return False

    def _trash_sender_emails(self, sender_id: str, account_email: str) -> int:
        """Move all emails from this sender to trash. Returns count moved."""
        account = self._get_account(account_email)
        if not account:
            return 0
        try:
            mail = self._connect(account)
            mail.select("INBOX")
            _, ids = mail.search(None, f'FROM "{sender_id}"')
            count = 0
            for uid in ids[0].split():
                mail.store(uid, "+FLAGS", "\\Deleted")
                count += 1
            if count:
                mail.expunge()
            mail.logout()
            return count
        except Exception as e:
            log.warning(f"Could not trash emails: {e}")
            return 0

    # ── ACTION 3: Mark as Safe ───────────────────────────────────────────────
    def mark_safe(self, sender: str, account_email: str = "") -> dict:
        """Add sender to safe list. Remove from blocklist if present."""
        domain     = self._extract_domain(sender)
        full_email = self._extract_email(sender)

        if not domain:
            return {"success": False, "message": "Could not extract sender info"}

        try:
            # add to safe domains
            self.storage.update_learned("safe_domains", domain)
            if full_email:
                self.storage.update_learned("safe_domains", full_email)

            # remove from blocked list
            patterns = self.storage.learned_patterns
            blocked  = patterns.get("blocked_senders", [])
            changed  = False
            for item in [domain, full_email]:
                if item and item in blocked:
                    blocked.remove(item)
                    changed = True
            if changed:
                patterns["blocked_senders"] = blocked
                self.storage.save("learned_patterns.json", patterns)

            # unblock from hosts file if present
            if domain not in NEVER_BLOCK_DOMAINS:
                self._unblock_dns(domain)

            self._log_action("mark_safe", account_email, f"Safe: {sender}")
            log.info(f"Marked safe: {sender}")
            return {
                "success": True,
                "message": f"'{full_email or domain}' added to safe list\nWill never be flagged again"
            }
        except Exception as e:
            log.error(f"Mark safe failed: {e}")
            return {"success": False, "message": str(e)}

    # ── ACTION 4: Unblock ────────────────────────────────────────────────────
    def unblock_sender(self, identifier: str) -> dict:
        """Remove email/domain from blocklist and hosts file."""
        try:
            patterns = self.storage.learned_patterns
            blocked  = patterns.get("blocked_senders", [])
            if identifier in blocked:
                blocked.remove(identifier)
                patterns["blocked_senders"] = blocked
                self.storage.save("learned_patterns.json", patterns)
            self._unblock_dns(identifier)
            return {"success": True, "message": f"'{identifier}' unblocked"}
        except Exception as e:
            return {"success": False, "message": str(e)}

    def _unblock_dns(self, domain: str):
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        try:
            with open(hosts_path, "r") as f:
                lines = f.readlines()
            new_lines = [
                l for l in lines
                if not (domain in l and "ThreatShield-blocked" in l)
            ]
            with open(hosts_path, "w") as f:
                f.writelines(new_lines)
            log.info(f"DNS unblocked: {domain}")
        except PermissionError:
            log.warning("Need admin rights to unblock from hosts file")
        except Exception as e:
            log.warning(f"Could not unblock DNS: {e}")

    # ── helpers ──────────────────────────────────────────────────────────────
    def _extract_domain(self, sender: str) -> str:
        m = re.search(r"@([\w.\-]+)", sender)
        return m.group(1).lower() if m else ""

    def _extract_email(self, sender: str) -> str:
        m = re.search(r"[\w.\-+]+@[\w.\-]+", sender)
        return m.group(0).lower() if m else ""

    def _log_action(self, action: str, account: str, detail: str):
        import time
        actions = self.storage.config.get("user_actions", [])
        actions.append({
            "action":    action,
            "account":   account,
            "detail":    detail,
            "timestamp": time.time(),
        })
        self.storage.config["user_actions"] = actions[-100:]
        self.storage.save("config.json", self.storage.config)


    # ── ACTION: Block Domain ─────────────────────────────────────────────────
    def block_domain(self, domain: str) -> dict:
        """
        Block a malicious domain found in email URLs.
        - Adds to local blocklist
        - Blocks at DNS level (hosts file)
        - Shared with web shield so browser also blocks it
        """
        if not domain:
            return {"success": False, "message": "No domain provided"}

        messages = []
        try:
            # add to local url blocklist
            self.storage.update_learned("blocked_senders", domain)

            # also add to url_cache as malicious
            # so web shield instantly blocks it too
            import time
            cache = self.storage.url_cache
            cache[f"http://{domain}"]  = {"safe": False, "checked_at": time.time()}
            cache[f"https://{domain}"] = {"safe": False, "checked_at": time.time()}
            self.storage.save("url_cache.json", cache)
            messages.append(f"Domain '{domain}' added to block list")

            # DNS block
            dns = self._block_dns(domain)
            if dns["success"]:
                messages.append(f"Blocked at DNS level — site cannot load on this device")
            elif dns["needs_admin"]:
                elevated = self._request_admin_elevation(domain)
                if elevated:
                    messages.append("Blocked at DNS level via admin elevation")
                else:
                    messages.append("DNS blocking needs Administrator — right-click ThreatShield > Run as Administrator")

            self._log_action("block_domain", "", f"Blocked domain: {domain}")
            log.info(f"Domain blocked: {domain}")
            return {"success": True, "message": "\n".join(messages)}

        except Exception as e:
            log.error(f"Block domain failed: {e}")
            return {"success": False, "message": str(e)}

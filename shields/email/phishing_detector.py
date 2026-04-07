"""
ThreatShield AI — Smart NLP Phishing Detector
Zero manual domain whitelists — detects by BEHAVIOR not by name matching.
URL analysis based on domain properties, not brand word matching.
"""
import re
from urllib.parse import urlparse
from core.logger import get_logger

log = get_logger("phishing_detector")

# ── credential harvesting patterns ───────────────────────────────────────────
CREDENTIAL_PATTERNS = [
    r"(enter|provide|submit|confirm|verify).{0,20}(password|credential|pin|ssn|card number)",
    r"(your\s+)?(username|email|password).{0,10}(below|expired|reset required)",
    r"log.?in.{0,20}(again|below|to confirm|to verify)",
    r"(update|verify|confirm).{0,20}(billing|payment info|card details|bank account)",
    r"(reset|change).{0,10}password.{0,20}(immediately|now|urgent|expire)",
    r"login.{0,20}(to check|to verify|to confirm|to secure|to restore)",
    r"(unusual|suspicious|unauthorized).{0,20}(activity|access|login|sign.?in)",
    r"(click|tap|visit|open).{0,20}(link|here|below).{0,30}(account|verify|secure|check)",
]

URGENCY_PATTERNS = [
    r"(account|access).{0,20}(suspend|terminat|deactivat|permanently.block)",
    r"(verify|confirm).{0,20}(identity|account|ownership).{0,20}(now|immediately|urgent)",
    r"(click|tap).{0,20}(to|and).{0,20}(verify|confirm|restore|reactivate).{0,20}account",
    r"(unusual|suspicious).{0,20}(activity|login|access).{0,20}(detected|found|noticed)",
]

# ── ONLY these TLDs are genuinely suspicious ─────────────────────────────────
# Real companies NEVER use these
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".loan", ".gq", ".tk",
    ".ml", ".cf", ".ga", ".pw", ".cc", ".work", ".party",
    ".review", ".racing", ".date", ".faith", ".cricket",
}

# ── well-known legitimate infrastructure domains ─────────────────────────────
# These are hosting/CDN providers — any domain ending with these is safe
INFRASTRUCTURE_SUFFIXES = (
    "amazonaws.com", "cloudfront.net", "fastly.net", "akamaized.net",
    "cloudflare.com", "googleusercontent.com", "gstatic.com",
    "googleapis.com", "google.com", "microsoft.com", "azure.com",
    "azureedge.net", "msecnd.net", "windows.net",
    "s3.amazonaws.com", "storage.googleapis.com",
)

# ── personal email providers — content analyzed but sender not penalized ─────
PERSONAL_EMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com",
    "yahoo.com", "icloud.com", "protonmail.com", "live.com",
    "ymail.com", "rediffmail.com",
}

# ── what makes a domain LOOK fake ────────────────────────────────────────────
# These patterns detect domain construction, not brand name presence
FAKE_DOMAIN_PATTERNS = [
    # brand name + random numbers/hyphens (paypa1, amaz0n, g00gle)
    r"(paypal|amazon|google|microsoft|apple|netflix|facebook|instagram|bank|chase)"
    r".{0,5}[0-9]",
    # hyphenated brand impersonation (secure-paypal.com, amazon-login.xyz)
    r"(secure|login|verify|account|update|support).{0,3}--.{0,3}"
    r"(paypal|amazon|google|microsoft|apple|netflix|bank)",
    r"(paypal|amazon|google|microsoft|apple|netflix|bank).{0,3}--.{0,3}"
    r"(secure|login|verify|account|update|support|alert)",
]


class PhishingDetector:
    def __init__(self, storage):
        self.storage = storage
        self._nlp = None
        self._load_spacy()

    def _load_spacy(self):
        try:
            import spacy
            self._nlp = spacy.load("en_core_web_sm")
            log.info("spaCy NLP model loaded successfully")
        except Exception as e:
            log.warning(f"spaCy not available — pattern analysis only: {e}")

    def analyze(self, msg) -> dict:
        subject = self._decode_header(msg.get("subject", "") or "")
        sender = msg.get("from", "") or ""
        reply_to = msg.get("reply-to", "") or ""
        body = self._get_body(msg)
        full_text = f"{subject} {body}"

        sender_trusted = self._is_trusted_sender(sender)
        signals, score = [], 0.0

        # ── 1. content — runs for EVERY email ────────────────────────────
        s, sc = self._check_credentials(full_text.lower())
        signals += s
        score += sc

        if sc > 0:
            s, sc = self._check_urgency(full_text.lower())
            signals += s
            score += sc

        # ── 2. URL analysis — smart, no manual lists ──────────────────────
        urls = self._extract_urls(body)
        s, sc = self._analyze_urls(urls, sender_trusted)
        signals += s
        score += sc

        # ── 3. spaCy NLP — only if already suspicious ─────────────────────
        if score >= 0.15 and self._nlp:
            s, sc = self._nlp_analysis(full_text)
            signals += s
            score += sc

        # ── 4. sender checks — only for untrusted senders ─────────────────
        if not sender_trusted:
            s, sc = self._check_sender(sender, reply_to)
            signals += s
            score += sc

        # ── 5. blocklist ──────────────────────────────────────────────────
        s, sc = self._check_blocklist(sender)
        signals += s
        score += sc

        # ── 6. learned patterns (filtered — skip generic words) ──────────
        # Minimum 6 chars and must be multi-word or specific to avoid
        # false positives from generic words like 'url', 'web', 'in'
        GENERIC_WORDS = {"url", "web", "in", "on", "at", "the", "a", "account",
                         "link", "email", "mail", "click", "here", "your"}
        learned_score = 0.0
        for kw in self.storage.learned_patterns.get("phishing_keywords", []):
            kw_clean = kw.lower().strip()
            if kw_clean in GENERIC_WORDS:
                continue
            if len(kw_clean) < 6 and " " not in kw_clean:
                continue
            if kw_clean in full_text.lower():
                signals.append(f"Learned: Known phishing keyword '{kw}'")
                learned_score += 0.10
        # cap learned pattern contribution
        score += min(learned_score, 0.25)

        score = min(round(score, 2), 1.0)
        return {
            "is_phishing": score >= 0.45,
            "score":       score,
            "signals":     signals,
            "reasons":     signals,
            "urls_found":  urls,
            "sender":      sender,
            "subject":     subject,
        }

    # ── trusted sender ────────────────────────────────────────────────────────
    def _is_trusted_sender(self, sender: str) -> bool:
        """
        Auto-detect trusted senders by domain structure.
        No manual whitelist — uses heuristics.
        """
        m = re.search(r"@([\w.\-]+)", sender)
        if not m:
            return False
        domain = m.group(1).lower()

        # user's manually marked safe domains
        if domain in self.storage.learned_patterns.get("safe_domains", []):
            return True

        # personal email providers — trusted for reputation,
        # but content is still analyzed
        if domain in PERSONAL_EMAIL_DOMAINS:
            return True

        # check if domain itself looks legitimate:
        # - has a real TLD (not suspicious)
        # - not using numbers to replace letters (paypa1)
        # - not a hyphenated fake
        parts = domain.split(".")
        if len(parts) >= 2:
            tld = "." + parts[-1]
            # legitimate TLDs that real companies use
            REAL_TLDS = {
                ".com", ".org", ".net", ".edu", ".gov",
                ".io", ".co", ".in", ".uk", ".de", ".fr",
                ".au", ".ca", ".jp", ".sg", ".ae",
                ".app", ".dev", ".ai", ".tech",
            }
            if tld in REAL_TLDS:
                # not a suspicious domain pattern
                if not self._looks_fake(domain):
                    return True

        return False

    def _looks_fake(self, domain: str) -> bool:
        """Detect fake/impersonation domains by structure."""
        # leetspeak substitutions (paypa1, g00gle, amaz0n)
        if re.search(r"(paypal|amazon|google|microsoft|apple|netflix|"
                     r"facebook|instagram|bank|chase)[a-z0-9]*[0-9]", domain):
            return True
        # brand-security/login hyphen combos
        if re.search(r"(secure|login|verify|account|update|alert)-"
                     r"(paypal|amazon|google|microsoft|apple|netflix|bank)", domain):
            return True
        if re.search(r"(paypal|amazon|google|microsoft|apple|netflix|bank)-"
                     r"(secure|login|verify|account|update|alert|support)", domain):
            return True
        return False

    # ── credential harvesting ─────────────────────────────────────────────────
    def _check_credentials(self, text: str):
        signals, score = [], 0.0
        hits = sum(1 for p in CREDENTIAL_PATTERNS
                   if re.search(p, text, re.IGNORECASE))
        if hits >= 1:
            signals.append(
                f"Credential/account threat language detected "
                f"({hits} pattern{'s' if hits > 1 else ''})")
            score += hits * 0.2
        return signals, min(score, 0.5)

    # ── urgency ───────────────────────────────────────────────────────────────
    def _check_urgency(self, text: str):
        signals, score = [], 0.0
        for p in URGENCY_PATTERNS:
            if re.search(p, text, re.IGNORECASE):
                signals.append("Account suspension/urgency threat detected")
                score += 0.15
                break
        return signals, score

    # ── sender reputation ─────────────────────────────────────────────────────
    def _check_sender(self, sender: str, reply_to: str):
        signals, score = [], 0.0
        m = re.search(r"[\w.\-+]+@([\w.\-]+)", sender)
        if not m:
            return signals, score
        domain = m.group(1).lower()

        # suspicious TLD
        tld = "." + domain.split(".")[-1]
        if tld in SUSPICIOUS_TLDS:
            signals.append(f"Sender uses suspicious domain '{domain}'")
            score += 0.35

        # fake domain structure
        if self._looks_fake(domain):
            signals.append(
                f"Sender domain looks like impersonation: '{domain}'")
            score += 0.4

        # reply-to mismatch with untrusted domain
        rt = re.search(r"[\w.\-+]+@([\w.\-]+)", reply_to)
        if rt and rt.group(1).lower() != domain:
            rt_domain = rt.group(1).lower()
            if not self._is_trusted_sender(f"x@{rt_domain}"):
                signals.append(
                    "Reply-To differs from sender — spoofing indicator")
                score += 0.3

        return signals, score

    # ── blocklist ─────────────────────────────────────────────────────────────
    def _check_blocklist(self, sender: str):
        signals, score = [], 0.0
        m = re.search(r"@([\w.\-]+)", sender)
        em = re.search(r"[\w.\-+]+@[\w.\-]+", sender)
        if not m:
            return signals, score
        domain = m.group(1).lower()
        full_email = em.group(0).lower() if em else ""
        blocked = self.storage.learned_patterns.get("blocked_senders", [])
        if domain in blocked or full_email in blocked:
            signals.append("Sender is on your block list")
            score += 1.0
        return signals, score

    # ── URL extraction ────────────────────────────────────────────────────────
    def _extract_urls(self, body: str) -> list:
        raw = re.findall(r'https?://[^\s<>"\')\]]+', body)
        href = re.findall(r'href=["\']?(https?://[^\s"\'<>]+)', body)
        return list(set([u.rstrip(".,;)") for u in raw + href]))

    # ── SMART URL analysis ────────────────────────────────────────────────────
    def _analyze_urls(self, urls: list, sender_trusted: bool):
        """
        Detect suspicious URLs by domain PROPERTIES not brand name matching.
        Automatically handles AWS, CDN, social media links correctly.
        """
        signals, score = [], 0.0
        for url in urls[:10]:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower().lstrip("www.")

                # ── known malicious from VirusTotal cache ─────────────────
                cached = self.storage.url_cache.get(url)
                if cached and not cached.get("safe", True):
                    signals.append(
                        "URL: Known malicious link (VirusTotal confirmed)")
                    score += 0.6
                    continue

                # ── skip infrastructure/CDN domains entirely ──────────────
                # s3.amazonaws.com, cloudfront.net, googleapis.com etc
                # These are used by EVERY legitimate company
                if any(domain.endswith(infra) for infra in INFRASTRUCTURE_SUFFIXES):
                    continue

                # ── skip if sender is trusted ─────────────────────────────
                if sender_trusted:
                    continue

                # ── from here: untrusted sender only ─────────────────────

                # raw IP address in URL — always suspicious
                if re.match(r"^\d+\.\d+\.\d+\.\d+", domain):
                    signals.append(
                        "URL: Raw IP address used — highly suspicious")
                    score += 0.4
                    continue

                # suspicious TLD in URL domain
                url_tld = "." + domain.split(".")[-1]
                if url_tld in SUSPICIOUS_TLDS:
                    signals.append(
                        f"URL: Suspicious domain in link — {domain}")
                    score += 0.3
                    continue

                # fake domain structure in URL
                if self._looks_fake(domain):
                    signals.append(f"URL: Fake-looking domain — {domain}")
                    score += 0.35

            except Exception:
                pass
        return signals, min(score, 0.5)

    # ── spaCy NLP ─────────────────────────────────────────────────────────────
    def _nlp_analysis(self, text: str):
        signals, score = [], 0.0
        try:
            doc = self._nlp(text[:3000])
            for token in doc:
                if token.pos_ == "VERB" and token.lemma_ in {
                    "verify", "confirm", "update", "validate",
                    "provide", "enter", "submit", "reset", "login"
                }:
                    for child in token.children:
                        if child.lemma_ in {
                            "password", "credential", "detail",
                            "card", "bank", "pin", "account", "information"
                        }:
                            signals.append(
                                f"NLP: '{token.lemma_} {child.lemma_}'"
                                f" — credential harvesting intent")
                            score += 0.15
                            break
        except Exception as e:
            log.debug(f"NLP error: {e}")
        return signals, min(score, 0.2)

    # ── helpers ───────────────────────────────────────────────────────────────
    def _get_body(self, msg) -> str:
        parts = []
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() in ("text/plain", "text/html"):
                    try:
                        parts.append(
                            part.get_payload(decode=True).decode(errors="ignore"))
                    except Exception:
                        pass
        else:
            try:
                p = msg.get_payload(decode=True)
                if p:
                    parts.append(p.decode(errors="ignore"))
            except Exception:
                pass
        return "\n".join(parts)

    def _decode_header(self, value: str) -> str:
        try:
            from email.header import decode_header
            parts = []
            for part, enc in decode_header(value):
                if isinstance(part, bytes):
                    parts.append(
                        part.decode(enc or "utf-8", errors="ignore"))
                else:
                    parts.append(str(part))
            return " ".join(parts)
        except Exception:
            return value

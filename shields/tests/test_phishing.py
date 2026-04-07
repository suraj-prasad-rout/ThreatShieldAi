import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from unittest.mock import MagicMock
from shields.email.phishing_detector import PhishingDetector
import email.message

def _mock_storage():
    s = MagicMock()
    s.learned_patterns = {"phishing_keywords": [], "safe_senders": []}
    s.url_cache = {}
    return s

def _make_msg(subject, body, sender="user@legit-company.com"):
    msg = email.message.EmailMessage()
    msg["subject"] = subject
    msg["from"]    = sender
    msg.set_payload(body)
    return msg

def test_clean_email_is_safe():
    d = PhishingDetector(_mock_storage())
    r = d.analyze(_make_msg("Team lunch Friday?", "Hey, lunch at 1pm works for me."))
    assert r["is_phishing"] is False
    assert r["score"] < 0.4

def test_obvious_phishing_detected():
    d = PhishingDetector(_mock_storage())
    r = d.analyze(_make_msg(
        "Verify your account now",
        "Click here immediately — your account will be suspended. Confirm your password.",
    ))
    assert r["is_phishing"] is True
    assert r["score"] >= 0.4
    assert len(r["reasons"]) >= 2

def test_learned_keyword_raises_score():
    storage = _mock_storage()
    storage.learned_patterns["phishing_keywords"] = ["crypto giveaway"]
    d = PhishingDetector(storage)
    r = d.analyze(_make_msg("You won!", "Huge crypto giveaway — act now!"))
    assert r["score"] > 0.0

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from core.storage import Storage

def test_log_threat():
    s = Storage()
    before = len(s.threat_log)
    s.log_threat({"shield": "test", "msg": "unit test entry"})
    s2 = Storage()
    assert len(s2.threat_log) == before + 1, "Threat was not persisted to disk"

def test_url_cache():
    s = Storage()
    s.cache_url("https://example.com/test", True)
    assert s.url_cache["https://example.com/test"]["safe"] is True

def test_update_learned():
    s = Storage()
    s.update_learned("phishing_keywords", "test_keyword_xyz")
    s2 = Storage()
    assert "test_keyword_xyz" in s2.learned_patterns["phishing_keywords"]

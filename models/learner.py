"""
ThreatShield AI — Local Machine Learning Model
Fix: handle single-class training data gracefully
"""
import json
import time
import threading
from pathlib import Path
from core.logger import get_logger

log = get_logger("learner")

MODEL_FILE = Path(__file__).parent / "threat_model.pkl"


class LocalLearner:
    def __init__(self, storage):
        self.storage = storage
        self._model = None
        self._trained = False
        self._lock = threading.Lock()
        self._load_model()

    def _load_model(self):
        try:
            import pickle
            if MODEL_FILE.exists():
                with open(MODEL_FILE, "rb") as f:
                    self._model = pickle.load(f)
                self._trained = True
                log.info("Existing model loaded")
        except Exception as e:
            log.debug(f"Model load: {e}")

    def train(self):
        try:
            from sklearn.pipeline import Pipeline
            from sklearn.linear_model import LogisticRegression
            from sklearn.feature_extraction.text import TfidfVectorizer
            import pickle
        except ImportError:
            log.warning(
                "scikit-learn not installed — pip install scikit-learn")
            return

        threats = self.storage.threat_log
        if len(threats) < 5:
            return

        X, y = [], []
        for t in threats:
            text = " ".join(filter(None, [
                t.get("subject", ""), t.get("url", ""),
                t.get("file", ""),    t.get("reason", ""),
                t.get("type", ""),    t.get("shield", ""),
                " ".join(t.get("signals", []) or []),
            ])).strip()
            if not text:
                continue
            # label
            action = t.get("action", "")
            label = 0 if action == "allowed_by_user" else 1
            X.append(text)
            y.append(label)

        if len(X) < 5:
            return

        # CRITICAL FIX: need at least 2 classes to train
        # If all samples are class 1 (threats), add synthetic safe samples
        unique_classes = set(y)
        if len(unique_classes) < 2:
            log.info(
                f"Only class {unique_classes} in data — "
                f"adding synthetic safe samples for training balance")
            safe_samples = [
                "newsletter subscription update",
                "receipt order confirmation invoice",
                "meeting calendar invite tomorrow",
                "software update available version",
                "weather forecast sunny tomorrow",
            ]
            for s in safe_samples:
                X.append(s)
                y.append(0)

        with self._lock:
            try:
                pipe = Pipeline([
                    ("tfidf", TfidfVectorizer(
                        max_features=2000,
                        ngram_range=(1, 2),
                        min_df=1)),
                    ("clf",  LogisticRegression(
                        max_iter=1000,
                        class_weight="balanced")),
                ])
                pipe.fit(X, y)
                self._model = pipe
                self._trained = True
                with open(MODEL_FILE, "wb") as f:
                    pickle.dump(pipe, f)
                log.info(
                    f"Model retrained on {len(X)} samples "
                    f"(classes: {sorted(set(y))}) -> {MODEL_FILE}")
                self._extract_patterns(pipe)
            except Exception as e:
                log.error(f"Training error: {e}")

    def predict(self, text: str) -> float:
        if not self._trained or not self._model:
            return 0.5
        with self._lock:
            try:
                return float(self._model.predict_proba([text])[0][1])
            except Exception:
                return 0.5

    def _extract_patterns(self, model):
        try:
            feature_names = model.named_steps["tfidf"].get_feature_names_out()
            coefs = model.named_steps["clf"].coef_[0]
            top_idx = coefs.argsort()[-30:][::-1]
            keywords = [feature_names[i] for i in top_idx if coefs[i] > 0.1]
            if keywords:
                p = self.storage.learned_patterns
                existing = set(p.get("phishing_keywords", []))
                new_kw = [k for k in keywords[:20] if k not in existing]
                if new_kw:
                    p["phishing_keywords"] = list(existing)+new_kw
                    self.storage.save("learned_patterns.json", p)
                    log.info(
                        f"Learned {len(new_kw)} new patterns: {new_kw[:5]}")
        except Exception as e:
            log.debug(f"Pattern extraction: {e}")

    def start_background_loop(self, interval_seconds: int = 300):
        log.info("Background learning loop started")

        def _loop():
            self.train()
            while True:
                time.sleep(interval_seconds)
                try:
                    self.train()
                except Exception as e:
                    log.error(f"Training loop error: {e}")
        threading.Thread(target=_loop, daemon=True, name="ai-learner").start()

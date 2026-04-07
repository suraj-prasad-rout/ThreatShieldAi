"""Simple in-process pub/sub so shields can share findings without coupling."""
import threading
from collections import defaultdict

class EventBus:
    def __init__(self):
        self._listeners = defaultdict(list)
        self._lock = threading.Lock()

    def on(self, event: str, callback):
        with self._lock:
            self._listeners[event].append(callback)

    def emit(self, event: str, payload=None):
        with self._lock:
            listeners = list(self._listeners[event])
        for cb in listeners:
            threading.Thread(target=cb, args=(payload,), daemon=True).start()

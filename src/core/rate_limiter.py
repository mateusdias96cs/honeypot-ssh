import time
import threading
from collections import defaultdict

class IPRateLimiter:
    def __init__(self, max_connections: int, time_window: int):
        self.max_connections = max_connections
        self.time_window = time_window
        self.connections = defaultdict(list)
        self.lock = threading.Lock()

    def is_allowed(self, ip: str) -> bool:
        with self.lock:
            now = time.time()
            self.connections[ip] = [t for t in self.connections[ip] if now - t < self.time_window]
            if len(self.connections[ip]) >= self.max_connections:
                return False
            self.connections[ip].append(now)
            return True

"""Bounded, thread-safe temporary state. Deadlines use a monotonic clock."""

import threading
import time


class GrantStore:
    def __init__(self, *, clock=time.monotonic, capacity=10_000):
        self.clock, self.capacity = clock, capacity
        self._grants = {}
        self._lock = threading.Lock()

    def grant(self, channels, ip, seconds=300):
        with self._lock:
            now = self.clock()
            self._grants = {key: expiry for key, expiry in self._grants.items() if expiry > now}
            keys = {(channel, ip) for channel in channels}
            if len(self._grants.keys() | keys) > self.capacity:
                return False
            self._grants.update({key: now + seconds for key in keys})
            return True

    def allowed(self, channel, ip):
        with self._lock:
            key = (channel, ip)
            expiry = self._grants.get(key, 0)
            if expiry <= self.clock():
                self._grants.pop(key, None)
                return False
            return True


class LoginLimiter:
    """At most five attempts/IP/60s, including successful attempts."""

    def __init__(self, *, clock=time.monotonic, capacity=10_000):
        self.clock, self.capacity = clock, capacity
        self._attempts = {}
        self._lock = threading.Lock()

    def admit(self, ip):
        with self._lock:
            now = self.clock()
            current = self._attempts.get(ip)
            if current is not None and current[0] > now:
                if current[1] >= 5:
                    return False
                self._attempts[ip] = (current[0], current[1] + 1)
                return True
            if len(self._attempts) >= self.capacity:
                self._attempts = {
                    key: value for key, value in self._attempts.items() if value[0] > now
                }
                if len(self._attempts) >= self.capacity:
                    return False
            self._attempts[ip] = (now + 60, 1)
            return True

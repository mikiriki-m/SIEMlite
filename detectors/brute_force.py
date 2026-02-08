from collections import defaultdict, deque
from datetime import timedelta

class BruteForceDetector:
    def __init__(self, threshold=10, window_seconds=60):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self.attempts = defaultdict(deque)

    def process_event(self, event):
        if event["event"] != "FAILED_LOGIN":
            return None

        ip = event["ip"]
        timestamp = event["timestamp"]

        attempts = self.attempts[ip]
        attempts.append(timestamp)

        while attempts and timestamp - attempts[0] > self.window:
            attempts.popleft()

        if len(attempts) >= self.threshold:
            alert_data = {
                "alert_type": "SSH_BRUTE_FORCE",
                "ip": ip,
                "attempts": len(attempts),
                "time_window_seconds": self.window.seconds,
                "severity": "HIGH"
            }

            self.attempts.pop(ip)

            return alert_data

        return None
from collections import defaultdict, deque
from datetime import timedelta


class UserEnumerationDetector:
    def __init__(self, threshold=5, window_seconds=60):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self.attempts = defaultdict(deque)

    def process_event(self, event):
        if event["event"] != "FAILED_LOGIN":
            return None

        ip = event["ip"]
        user = event.get("user", "unknown")
        timestamp = event["timestamp"]

        user = event.get("user")

        attempts = self.attempts[ip]
        attempts.append((timestamp, user))

        while attempts and timestamp - attempts[0][0] > self.window:
            attempts.popleft()

        unique_users = {attempt[1] for attempt in attempts}

        if len(unique_users) >= self.threshold:
            alert_data = {
                "alert_type": "USER_ENUMERATION_ATTACK",
                "ip": ip,
                "unique_users_tried": list(unique_users),
                "count": len(unique_users),
                "severity": "MEDIUM"
            }

            self.attempts.pop(ip)

            return alert_data

        return None
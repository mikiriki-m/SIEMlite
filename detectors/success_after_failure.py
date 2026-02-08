from collections import defaultdict

class SuccessAfterFailureDetector:
    def __init__(self, failure_threshold=3):
        self.failure_threshold = failure_threshold
        self.failed_counts = defaultdict(int)

    def process_event(self, event):
        ip = event["ip"]
        user = event["user"]

        if event["event"] == "FAILED_LOGIN":
            self.failed_counts[ip] += 1
            return None

        if event["event"] == "SUCCESSFUL_LOGIN":
            failures = self.failed_counts.get(ip, 0)

            if failures >= self.failure_threshold:
                alert = {
                    "alert_type": "SUCCESS_AFTER_BRUTE_FORCE",
                    "ip": ip,
                    "user": user,
                    "previous_failures": failures,
                    "severity": "CRITICAL"
                }
                self.failed_counts.pop(ip, None)
                return alert

            self.failed_counts.pop(ip, None)

        return None
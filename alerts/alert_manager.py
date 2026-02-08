from database.db_handler import DatabaseHandler
from datetime import datetime, timedelta
import json

class AlertManager:
    def __init__(self, alert_file="alerts/alerts.log", cooldown_seconds=0):
        self.alert_file = alert_file
        self.cooldown = timedelta(seconds=cooldown_seconds)
        self.last_alerts = {}
        self.db = DatabaseHandler()

    def send(self, alert):
        ip = alert["ip"]
        alert_type = alert["alert_type"]
        now = datetime.now()

        alert_key = (ip, alert_type)
        if alert_key in self.last_alerts:
            if now - self.last_alerts[alert_key] < self.cooldown:
                return

        self.last_alerts[alert_key] = now
        alert["timestamp"] = now.isoformat()

        value = (alert.get("attempts") or
                 alert.get("count") or
                 alert.get("previous_failures") or
                 "N/A")

        severity = alert.get("severity", "INFO")
        message = (
            f"[{alert['timestamp']}] "
            f"{severity:<8} | "
            f"{alert_type:<25} | "
            f"IP={ip:<15} | Value={value}"
        )

        print(message)

        with open(self.alert_file, "a") as f:
            f.write(json.dumps(alert) + "\n")

        self.db.insert_alert(alert)
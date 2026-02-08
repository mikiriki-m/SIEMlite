import sqlite3

class DatabaseHandler:
    def __init__(self, db_path="alerts/alerts.db"):
        self.db_path = db_path
        self._create_table()

    def _create_table(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    severity TEXT,
                    alert_type TEXT,
                    ip TEXT,
                    user TEXT,
                    value TEXT
                )
            ''')
            conn.commit()

    def insert_alert(self, alert):
        value = (alert.get("attempts") or
                 alert.get("count") or
                 alert.get("previous_failures") or
                 "N/A")

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO alerts (timestamp, severity, alert_type, ip, user, value)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                alert.get("timestamp"),
                alert.get("severity"),
                alert.get("alert_type"),
                alert.get("ip"),
                alert.get("user", "N/A"),
                str(value)
            ))
            conn.commit()
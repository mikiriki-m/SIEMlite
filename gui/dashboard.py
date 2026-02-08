import tkinter as tk
from tkinter import ttk
import sqlite3
import os

class SIEMDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("SIEMlite - Security Operations Center")
        self.root.geometry("1100x700")
        self.root.configure(bg="#0f172a")

        self.header_frame = tk.Frame(self.root, bg="#1e293b", height=80)
        self.header_frame.pack(fill="x")

        tk.Label(
            self.header_frame, text="SIEMlite Live Monitor",
            font=("Segoe UI", 20, "bold"), fg="#38bdf8", bg="#1e293b", padx=20, pady=15
        ).pack(side="left")

        self.stats_ribbon = tk.Frame(self.root, bg="#0f172a", pady=20)
        self.stats_ribbon.pack(fill="x", padx=20)

        self.total_lbl = self.add_kpi_card("TOTAL EVENTS", "#94a3b8", 0)
        self.crit_lbl = self.add_kpi_card("CRITICAL THREATS", "#ef4444", 1)
        self.ip_lbl = self.add_kpi_card("UNIQUE ATTACKERS", "#f59e0b", 2)

        self.container = tk.Frame(self.root, bg="#0f172a")
        self.container.pack(expand=True, fill="both", padx=20, pady=10)

        self.setup_table()

        self.actions = tk.Frame(self.root, bg="#1e293b", pady=10)
        self.actions.pack(fill="x", side="bottom")

        tk.Button(
            self.actions, text="REFRESH FEED", command=self.update_data,
            bg="#0ea5e9", fg="white", font=("Segoe UI", 10, "bold"),
            padx=20, relief="flat", cursor="hand2"
        ).pack(side="right", padx=20)

        self.update_data()

    def add_kpi_card(self, title, color, column):
        card = tk.Frame(self.stats_ribbon, bg="#1e293b", padx=30, pady=15, highlightthickness=1,
                        highlightbackground="#334155")
        card.grid(row=0, column=column, padx=10, sticky="nsew")
        self.stats_ribbon.grid_columnconfigure(column, weight=1)

        tk.Label(card, text=title, font=("Segoe UI", 9, "bold"), fg=color, bg="#1e293b").pack()
        val_label = tk.Label(card, text="0", font=("Consolas", 24, "bold"), fg="white", bg="#1e293b")
        val_label.pack()
        return val_label

    def setup_table(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#1e293b", foreground="#e2e8f0", fieldbackground="#1e293b", rowheight=35,
                        borderwidth=0)
        style.configure("Treeview.Heading", background="#334155", foreground="white", font=("Segoe UI", 10, "bold"),
                        borderwidth=0)
        style.map("Treeview", background=[('selected', '#0ea5e9')])

        self.tree = ttk.Treeview(self.container, columns=("time", "sev", "type", "ip", "val"), show="headings")

        cols = {"time": "Timestamp", "sev": "Severity", "type": "Alert Type", "ip": "Source IP", "val": "Metric"}
        for id, name in cols.items():
            self.tree.heading(id, text=name)
            self.tree.column(id, width=150, anchor="center")

        self.tree.pack(side="left", expand=True, fill="both")

        sb = ttk.Scrollbar(self.container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=sb.set)
        sb.pack(side="right", fill="y")

    def update_data(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        try:
            db_path = "alerts/alerts.db"
            if not os.path.exists(db_path):
                print(f"Database not found at {db_path}")
                return

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            cursor.execute(
                "SELECT COUNT(*), COUNT(CASE WHEN severity='CRITICAL' THEN 1 END), COUNT(DISTINCT ip) FROM alerts")
            total, crit, ips = cursor.fetchone()
            self.total_lbl.config(text=str(total))
            self.crit_lbl.config(text=str(crit))
            self.ip_lbl.config(text=str(ips))

            cursor.execute("SELECT timestamp, severity, alert_type, ip, value FROM alerts ORDER BY id DESC LIMIT 50")
            for row in cursor.fetchall():
                tag = row[1].upper()
                self.tree.insert("", "end", values=row, tags=(tag,))

            self.tree.tag_configure("CRITICAL", foreground="#ef4444")
            self.tree.tag_configure("HIGH", foreground="#f59e0b")
            self.tree.tag_configure("MEDIUM", foreground="#facc15")

            conn.close()
        except Exception as e:
            print(f"Database Error: {e}")

def create_dashboard():
    root = tk.Tk()
    app = SIEMDashboard(root)
    root.mainloop()
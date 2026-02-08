SIEMlite is a simple security montioring tool that focuses on SSH logs. Unlike basic log filters, SIEMlite uses sliding-window algorithms and stateful tracking to detect malicious behaviour.

Key Detection Features:

SSH BRUTE FORCE DETECTION
  Monitors login failures within a configurable time window and flags IP addresses that exceed the failed threshold attempts.

USER ENUMERATION TRACKING
  Identifies when an attacker is enumerating usernames by tracking attempts from a singular IP and sends an alert when multiple different accounts are targeted within a short window of time.

SUCCESS-AFTER-FAILURE
  Detects when a successful login occurs immediately after a series of failures from the same IP which is a strong indicator of a compromised account.

Montitoring and Logging Features:

LIVE DASHBOARD
  The dashboard contains real-time information, colour-coded threat levels, and KPI counters.
PERSISTENT LOGGING
  All security events are automatically logged to a database for forensics and audit trails.

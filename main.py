from parsers.ssh_parser import parse_ssh_line
from detectors.brute_force import BruteForceDetector
from detectors.user_enumeration import UserEnumerationDetector
from detectors.success_after_failure import SuccessAfterFailureDetector
from alerts.alert_manager import AlertManager
from gui.dashboard import create_dashboard

alarm = AlertManager(cooldown_seconds=0)

detectors = [
    BruteForceDetector(threshold=10, window_seconds=60),
    UserEnumerationDetector(threshold=5, window_seconds=60),
    SuccessAfterFailureDetector(failure_threshold=3)
]

with open("logs/SSH_test.log", "r") as f:
    for line in f:
        event = parse_ssh_line(line)
        if not event:
            continue

        for detector in detectors:
            alert = detector.process_event(event)
            if alert:
                alarm.send(alert)

if __name__ == "__main__":
    create_dashboard()
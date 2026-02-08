import re
from datetime import datetime

FAILED_SSH_REGEX = re.compile(
    r'^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*'
    r'(?P<status>Failed password for|Invalid user|Accepted password for|Accepted password)\s+(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)'
)

def parse_ssh_line(line: str):
    match = FAILED_SSH_REGEX.search(line)
    if not match:
        return None

    timestamp_str = match.group("timestamp")
    current_year = datetime.now().year
    timestamp = datetime.strptime(f"{timestamp_str} {current_year}", "%b %d %H:%M:%S %Y")

    log_status = match.group("status")
    event_type = "SUCCESSFUL_LOGIN" if "Accepted" in log_status else "FAILED_LOGIN"

    return {
        "timestamp": timestamp,
        "user": match.group("user"),
        "ip": match.group("ip"),
        "event": event_type
    }
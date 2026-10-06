import re

RULES = [
    {
        "name": "SSH Brute-Force / Failed Password",
        "pattern": re.compile(r"Failed password for (?:invalid user )?(\w+) from ([\d\.]+)"),
        "severity": "High",
        "extract": lambda m: (m.group(1), m.group(2)) # user, ip
    },
    {
        "name": "SSH Invalid User Enumeration",
        "pattern": re.compile(r"Invalid user (\w+) from ([\d\.]+)"),
        "severity": "Medium",
        "extract": lambda m: (m.group(1), m.group(2)) # user, ip
    },
    {
        "name": "Privilege Escalation (Sudo Command)",
        "pattern": re.compile(r"sudo:\s+([a-zA-Z0-9_\-\.]+)\s+:.*COMMAND=(.*)"),
        "severity": "Medium",
        "extract": lambda m: (m.group(1), "127.0.0.1") # user, local
    },
    {
        "name": "Root Session Opened",
        "pattern": re.compile(r"session opened for user root"),
        "severity": "Critical",
        "extract": lambda m: ("root", "127.0.0.1")
    }
]

def analyze_log_line(line: str):
    """
    Evaluates a single line of log text against signature detection rules.
    Returns: dict with detection metadata, or None if benign.
    """
    for rule in RULES:
        match = rule["pattern"].search(line)
        if match:
            user, ip = rule["extract"](match)
            return {
                "attack_type": rule["name"],
                "severity": rule["severity"],
                "user": user,
                "ip": ip,
                "raw_log": line.strip()
            }
    return None

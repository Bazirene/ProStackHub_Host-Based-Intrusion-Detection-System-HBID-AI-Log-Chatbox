import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from detector import analyze_log_line
from database import init_db, log_alert

LOG_FILE = "syslog.log"

class HIDSLogHandler(FileSystemEventHandler):
    def __init__(self, target_file):
        self.target_file = os.path.abspath(target_file)
        # Ensure log file exists
        if not os.path.exists(self.target_file):
            open(self.target_file, "a").close()
        # Track file read pointer (tail -f mechanism)
        self.file_pos = os.path.getsize(self.target_file)

    def on_modified(self, event):
        if os.path.abspath(event.src_path) != self.target_file:
            return

        with open(self.target_file, "r") as f:
            f.seek(self.file_pos)
            new_lines = f.readlines()
            self.file_pos = f.tell()

        for line in new_lines:
            if not line.strip():
                continue
            detection = analyze_log_line(line)
            if detection:
                log_alert(
                    source="auth.log",
                    attack_type=detection["attack_type"],
                    severity=detection["severity"],
                    raw_log=detection["raw_log"],
                    ip_address=detection["ip"]
                )
                print(f"[!] [ALERT] {detection['severity']} | {detection['attack_type']} | IP: {detection['ip']}")

def start_watcher():
    init_db()
    handler = HIDSLogHandler(LOG_FILE)
    observer = Observer()
    observer.schedule(handler, path=".", recursive=False)
    observer.start()
    print(f"[*] HIDS Active. Monitoring real-time event stream on '{LOG_FILE}'...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    start_watcher()

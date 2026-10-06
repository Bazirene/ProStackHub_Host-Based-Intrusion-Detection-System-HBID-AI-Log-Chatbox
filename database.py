import sqlite3

DB_NAME = "hids_events.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            source TEXT,
            attack_type TEXT,
            severity TEXT,
            raw_log TEXT,
            ip_address TEXT
        )
    """)
    conn.commit()
    conn.close()

def log_alert(source, attack_type, severity, raw_log, ip_address="N/A"):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO alerts (source, attack_type, severity, raw_log, ip_address)
        VALUES (?, ?, ?, ?, ?)
    """, (source, attack_type, severity, raw_log, ip_address))
    conn.commit()
    conn.close()

def get_recent_logs(limit=25):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT timestamp, source, attack_type, severity, raw_log, ip_address 
        FROM alerts ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows

if __name__ == "__main__":
    init_db()
    print("[+] HIDS SQLite Database initialized.")

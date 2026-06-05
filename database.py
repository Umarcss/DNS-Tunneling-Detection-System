import sqlite3

DB_NAME = "dns_security.db"


def get_conn():
    conn = sqlite3.connect(DB_NAME)
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS Client_Devices (
            device_id   INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address  TEXT UNIQUE NOT NULL,
            mac_address TEXT,
            device_name TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS DNS_Logs (
            log_id           INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id        INTEGER,
            timestamp        DATETIME DEFAULT CURRENT_TIMESTAMP,
            query_string     TEXT NOT NULL,
            query_type       TEXT,
            entropy_score    REAL,
            prediction_label TEXT CHECK(prediction_label IN ('Benign', 'Tunneling')),
            risk_score       REAL,
            FOREIGN KEY(device_id) REFERENCES Client_Devices(device_id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS Threat_Alerts (
            alert_id           INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id             INTEGER UNIQUE,
            alert_acknowledged INTEGER DEFAULT 0,
            FOREIGN KEY(log_id) REFERENCES DNS_Logs(log_id)
        )
    """)

    conn.commit()
    conn.close()


def log_dns_transaction(ip_address, query_string, query_type, entropy, label, risk_score):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        "INSERT OR IGNORE INTO Client_Devices (ip_address, device_name) VALUES (?, ?)",
        (ip_address, f"Host-{ip_address.split('.')[-1]}"),
    )
    cur.execute("SELECT device_id FROM Client_Devices WHERE ip_address = ?", (ip_address,))
    device_id = cur.fetchone()[0]

    cur.execute(
        """
        INSERT INTO DNS_Logs (device_id, query_string, query_type, entropy_score, prediction_label, risk_score)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (device_id, query_string, query_type, entropy, label, risk_score),
    )
    log_id = cur.lastrowid

    if label == "Tunneling":
        cur.execute(
            "INSERT OR IGNORE INTO Threat_Alerts (log_id) VALUES (?)",
            (log_id,),
        )

    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print("3NF SQLite Database initialized successfully.")

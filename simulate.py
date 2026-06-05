"""
Simulates a live DNS traffic stream — no root/sudo required.
Run this in a separate terminal WHILE the dashboard is open:
    python simulate.py
Press Ctrl+C to stop.
"""
import random
import string
import base64
import time
import ipaddress
from database import init_db, log_dns_transaction
from classifier import classify_dns_query

random.seed()

_BENIGN_DOMAINS = [
    "www.google.com", "mail.yahoo.com", "api.github.com", "cdn.netflix.com",
    "static.facebook.com", "www.microsoft.com", "login.amazon.com",
    "fonts.googleapis.com", "www.wikipedia.org", "api.twitter.com",
    "www.reddit.com", "media.tumblr.com", "update.dropbox.com",
    "www.stackoverflow.com", "mail.gmail.com", "docs.python.org",
    "assets.cloudflare.com", "img.shields.io", "www.youtube.com",
    "api.openai.com", "cdn.jsdelivr.net", "auth.ubuntu.com",
]

_C2_SUFFIXES = [
    "c2server.net", "tunnel.org", "dns-exfil.com", "relay.net",
    "payload.io", "botnet.com", "cnc.org", "callback.net",
]

_QTYPES = ["A", "AAAA", "TXT", "MX", "CNAME"]
_QTYPE_WEIGHTS = [50, 20, 15, 10, 5]


def _random_ip():
    return str(ipaddress.IPv4Address(random.randint(0xC0A80001, 0xC0A8FFFE)))


def _gen_benign_query():
    return random.choice(_BENIGN_DOMAINS)


def _gen_malicious_query():
    size = random.randint(20, 50)
    kind = random.choice(["base64", "hex", "random"])
    if kind == "base64":
        raw = "".join(random.choices(string.ascii_letters + string.digits, k=size))
        payload = base64.b64encode(raw.encode()).decode().replace("=", "").lower()
    elif kind == "hex":
        payload = "".join(random.choices("0123456789abcdef", k=min(size * 2, 60)))
    else:
        payload = "".join(random.choices(string.ascii_lowercase + string.digits, k=size))
    return f"{payload}.{random.choice(_C2_SUFFIXES)}"


def run_simulation(delay: float = 1.5, malicious_ratio: float = 0.20):
    init_db()
    print("DNS Traffic Simulator running — press Ctrl+C to stop.")
    print(f"  Interval: {delay}s | Malicious rate: {int(malicious_ratio*100)}%\n")

    total = 0
    threats = 0

    try:
        while True:
            is_malicious = random.random() < malicious_ratio
            query = _gen_malicious_query() if is_malicious else _gen_benign_query()
            ip = _random_ip()
            qtype = random.choices(_QTYPES, weights=_QTYPE_WEIGHTS, k=1)[0]

            entropy, label, risk = classify_dns_query(query)
            log_dns_transaction(ip, query, qtype, entropy, label, risk)

            total += 1
            if label == "Tunneling":
                threats += 1
                marker = "THREAT"
            else:
                marker = "      "

            print(
                f"[{marker}] {ip:>15}  {qtype:<5}  H={entropy:.2f}  "
                f"Risk={risk:>5.1f}%  {query[:60]}"
            )

            time.sleep(delay)

    except KeyboardInterrupt:
        print(f"\nSimulation stopped. Total: {total} queries | Threats detected: {threats}")


if __name__ == "__main__":
    run_simulation()

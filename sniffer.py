"""
Live DNS packet sniffer — requires root/sudo on Linux:
    sudo python sniffer.py

For demo/testing WITHOUT root, run simulate.py instead.
"""
from database import init_db, log_dns_transaction
from classifier import classify_dns_query

try:
    from scapy.all import sniff, DNS, DNSQR, IP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


_QTYPE_MAP = {1: "A", 28: "AAAA", 16: "TXT", 15: "MX", 5: "CNAME"}


def _packet_callback(packet):
    try:
        if not (packet.haslayer(DNS) and packet[DNS].qr == 0 and packet[DNS].qd):
            return
        src_ip = packet[IP].src if packet.haslayer(IP) else "127.0.0.1"
        query_string = packet[DNS].qd.qname.decode("utf-8").rstrip(".")
        qtype = _QTYPE_MAP.get(packet[DNS].qd.qtype, f"Type-{packet[DNS].qd.qtype}")

        entropy, label, risk = classify_dns_query(query_string)
        log_dns_transaction(src_ip, query_string, qtype, entropy, label, risk)

        marker = "THREAT" if label == "Tunneling" else "      "
        print(
            f"[{marker}] {src_ip:>15}  {qtype:<5}  H={entropy:.2f}  "
            f"Risk={risk:>5.1f}%  {query_string[:60]}"
        )
    except Exception:
        pass


def start_sniffer(interface=None):
    if not SCAPY_AVAILABLE:
        print("Scapy is not installed. Install it with: pip install scapy")
        return

    init_db()
    print("Live DNS Sniffer active — monitoring Port 53 traffic. Press Ctrl+C to stop.")
    sniff(
        filter="udp port 53 or tcp port 53",
        prn=_packet_callback,
        store=0,
        iface=interface,
    )


if __name__ == "__main__":
    start_sniffer()

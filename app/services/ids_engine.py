"""
Cyber Sentinel AI - Intrusion Detection Engine
Stateful, sliding-window analysis of packet events. Designed to be called
either from the live Scapy capture callback (see services/packet_capture.py)
or directly from tests with synthetic packet-event dictionaries — the
detection logic itself has no dependency on Scapy or a live NIC.

Detects: Port Scan, Ping Flood, SYN Flood, UDP Flood, ICMP Flood, FIN Scan,
NULL Scan, XMAS Scan, Brute Force, Network Scan, ARP Spoofing, DNS Spoofing,
Suspicious Connections, Repeated Failed Connections, Bandwidth Abuse,
Data Exfiltration.
"""
import ipaddress
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Optional, Tuple

from sqlalchemy.orm import Session

from app.models.alert import Alert

# ---------------------------------------------------------------------------
# Thresholds (tunable). All windows are in seconds.
# ---------------------------------------------------------------------------
PORT_SCAN_WINDOW = 10
PORT_SCAN_DISTINCT_PORTS_THRESHOLD = 15

NETWORK_SCAN_WINDOW = 15
NETWORK_SCAN_DISTINCT_HOSTS_THRESHOLD = 10

FLOOD_WINDOW = 5
SYN_FLOOD_THRESHOLD = 100
UDP_FLOOD_THRESHOLD = 150
ICMP_FLOOD_THRESHOLD = 50
PING_FLOOD_THRESHOLD = 50

SCAN_FLAG_WINDOW = 10
FIN_SCAN_THRESHOLD = 15
NULL_SCAN_THRESHOLD = 15
XMAS_SCAN_THRESHOLD = 15

BRUTE_FORCE_WINDOW = 30
BRUTE_FORCE_THRESHOLD = 8
BRUTE_FORCE_PORTS = {22, 21, 23, 3389, 445, 3306, 5432}

ARP_SPOOF_WINDOW = 60
DNS_SPOOF_WINDOW = 20

BANDWIDTH_ABUSE_WINDOW = 30
BANDWIDTH_ABUSE_BYTES_THRESHOLD = 50_000_000  # 50 MB in 30s from one host

DATA_EXFIL_WINDOW = 30
DATA_EXFIL_BYTES_THRESHOLD = 20_000_000  # 20 MB to a single external host in 30s

SUSPICIOUS_PORTS = {4444, 31337, 6667, 1337, 12345, 9001}

REPEATED_FAILED_CONN_WINDOW = 20
REPEATED_FAILED_CONN_THRESHOLD = 10


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


@dataclass
class _Window:
    """A simple (timestamp, value) sliding window keyed by an entity (usually src_ip)."""
    events: Dict[str, Deque[Tuple[float, object]]] = field(default_factory=lambda: defaultdict(deque))

    def add(self, key: str, value: object, now: float) -> None:
        self.events[key].append((now, value))

    def prune(self, key: str, now: float, window_seconds: float) -> None:
        dq = self.events[key]
        while dq and now - dq[0][0] > window_seconds:
            dq.popleft()

    def values(self, key: str):
        return [v for _, v in self.events[key]]


class IDSEngine:
    """
    Holds all sliding-window state. One instance should live for the lifetime
    of the capture session (or the app process for a always-on monitor).
    """

    def __init__(self) -> None:
        self.port_scan = _Window()          # key: src_ip -> dst_port
        self.network_scan = _Window()       # key: src_ip -> dst_ip
        self.syn_flood = _Window()          # key: dst_ip -> 1
        self.udp_flood = _Window()          # key: dst_ip -> 1
        self.icmp_flood = _Window()         # key: dst_ip -> 1
        self.fin_scan = _Window()           # key: src_ip -> 1
        self.null_scan = _Window()          # key: src_ip -> 1
        self.xmas_scan = _Window()          # key: src_ip -> 1
        self.brute_force = _Window()        # key: (src_ip,dst_port) -> 1
        self.arp_table: Dict[str, set] = defaultdict(set)          # ip -> {mac,...}
        self.arp_last_seen: Dict[str, float] = {}
        self.dns_answers: Dict[str, set] = defaultdict(set)        # domain -> {resolved_ip,...}
        self.dns_last_seen: Dict[str, float] = {}
        self.bandwidth = _Window()          # key: src_ip -> bytes
        self.exfil = _Window()              # key: (src_ip,dst_ip) -> bytes
        self.failed_conn = _Window()        # key: src_ip -> 1

    # -------------------------------------------------------------
    def process_event(self, db: Optional[Session], event: dict) -> list:
        """
        Process one packet event. `event` fields:
        timestamp(float), src_ip, dst_ip, src_port, dst_port, protocol (TCP/UDP/ICMP/ARP/DNS),
        size, ttl, flags (set of str among {SYN,ACK,FIN,RST,PSH,URG}), mac_address,
        dns_query (optional str), dns_answer_ip (optional str), connection_failed (bool, optional)
        Returns a list of Alert objects created (also persisted to `db` if provided).
        """
        now = event.get("timestamp") or time.time()
        alerts = []

        src_ip = event.get("src_ip")
        dst_ip = event.get("dst_ip")
        protocol = (event.get("protocol") or "").upper()
        flags = set(event.get("flags") or [])
        size = event.get("size", 0) or 0

        # ---- Port scan: many distinct destination ports from one src ----
        if src_ip and event.get("dst_port") is not None:
            self.port_scan.add(src_ip, event["dst_port"], now)
            self.port_scan.prune(src_ip, now, PORT_SCAN_WINDOW)
            distinct_ports = set(self.port_scan.values(src_ip))
            if len(distinct_ports) >= PORT_SCAN_DISTINCT_PORTS_THRESHOLD:
                alerts.append(self._raise(db, "port_scan", "high", src_ip, dst_ip,
                    f"{src_ip} probed {len(distinct_ports)} distinct ports within {PORT_SCAN_WINDOW}s"))
                self.port_scan.events[src_ip].clear()

        # ---- Network scan: many distinct destination hosts from one src ----
        if src_ip and dst_ip:
            self.network_scan.add(src_ip, dst_ip, now)
            self.network_scan.prune(src_ip, now, NETWORK_SCAN_WINDOW)
            distinct_hosts = set(self.network_scan.values(src_ip))
            if len(distinct_hosts) >= NETWORK_SCAN_DISTINCT_HOSTS_THRESHOLD:
                alerts.append(self._raise(db, "network_scan", "high", src_ip, None,
                    f"{src_ip} contacted {len(distinct_hosts)} distinct hosts within {NETWORK_SCAN_WINDOW}s"))
                self.network_scan.events[src_ip].clear()

        # ---- TCP flag-based scans & floods ----
        if protocol == "TCP":
            if flags == {"SYN"}:
                self.syn_flood.add(dst_ip, 1, now)
                self.syn_flood.prune(dst_ip, now, FLOOD_WINDOW)
                if len(self.syn_flood.values(dst_ip)) >= SYN_FLOOD_THRESHOLD:
                    alerts.append(self._raise(db, "syn_flood", "critical", src_ip, dst_ip,
                        f"SYN flood detected against {dst_ip}: {len(self.syn_flood.values(dst_ip))} SYNs in {FLOOD_WINDOW}s"))
                    self.syn_flood.events[dst_ip].clear()

            if flags == {"FIN"}:
                self.fin_scan.add(src_ip, 1, now)
                self.fin_scan.prune(src_ip, now, SCAN_FLAG_WINDOW)
                if len(self.fin_scan.values(src_ip)) >= FIN_SCAN_THRESHOLD:
                    alerts.append(self._raise(db, "fin_scan", "medium", src_ip, dst_ip,
                        f"FIN scan detected from {src_ip}"))
                    self.fin_scan.events[src_ip].clear()

            if len(flags) == 0:
                self.null_scan.add(src_ip, 1, now)
                self.null_scan.prune(src_ip, now, SCAN_FLAG_WINDOW)
                if len(self.null_scan.values(src_ip)) >= NULL_SCAN_THRESHOLD:
                    alerts.append(self._raise(db, "null_scan", "medium", src_ip, dst_ip,
                        f"NULL scan detected from {src_ip}"))
                    self.null_scan.events[src_ip].clear()

            if flags == {"FIN", "PSH", "URG"}:
                self.xmas_scan.add(src_ip, 1, now)
                self.xmas_scan.prune(src_ip, now, SCAN_FLAG_WINDOW)
                if len(self.xmas_scan.values(src_ip)) >= XMAS_SCAN_THRESHOLD:
                    alerts.append(self._raise(db, "xmas_scan", "medium", src_ip, dst_ip,
                        f"XMAS scan detected from {src_ip}"))
                    self.xmas_scan.events[src_ip].clear()

            # Brute force: repeated connection attempts to a sensitive service port
            if event.get("dst_port") in BRUTE_FORCE_PORTS and "SYN" in flags:
                bf_key = f"{src_ip}->{event.get('dst_port')}"
                self.brute_force.add(bf_key, 1, now)
                self.brute_force.prune(bf_key, now, BRUTE_FORCE_WINDOW)
                if len(self.brute_force.values(bf_key)) >= BRUTE_FORCE_THRESHOLD:
                    alerts.append(self._raise(db, "brute_force", "critical", src_ip, dst_ip,
                        f"Possible brute force from {src_ip} against port {event.get('dst_port')} on {dst_ip}"))
                    self.brute_force.events[bf_key].clear()

            # Suspicious ports (known malware/C2 ports)
            if event.get("dst_port") in SUSPICIOUS_PORTS or event.get("src_port") in SUSPICIOUS_PORTS:
                alerts.append(self._raise(db, "suspicious_connection", "high", src_ip, dst_ip,
                    f"Connection involving known suspicious port ({event.get('dst_port')})"))

            # Repeated failed connections (RST responses)
            if event.get("connection_failed"):
                self.failed_conn.add(src_ip, 1, now)
                self.failed_conn.prune(src_ip, now, REPEATED_FAILED_CONN_WINDOW)
                if len(self.failed_conn.values(src_ip)) >= REPEATED_FAILED_CONN_THRESHOLD:
                    alerts.append(self._raise(db, "repeated_failed_connection", "medium", src_ip, dst_ip,
                        f"{src_ip} had {len(self.failed_conn.values(src_ip))} failed connections in {REPEATED_FAILED_CONN_WINDOW}s"))
                    self.failed_conn.events[src_ip].clear()

        if protocol == "UDP":
            self.udp_flood.add(dst_ip, 1, now)
            self.udp_flood.prune(dst_ip, now, FLOOD_WINDOW)
            if len(self.udp_flood.values(dst_ip)) >= UDP_FLOOD_THRESHOLD:
                alerts.append(self._raise(db, "udp_flood", "critical", src_ip, dst_ip,
                    f"UDP flood detected against {dst_ip}"))
                self.udp_flood.events[dst_ip].clear()

        if protocol == "ICMP":
            self.icmp_flood.add(dst_ip, 1, now)
            self.icmp_flood.prune(dst_ip, now, FLOOD_WINDOW)
            icmp_count = len(self.icmp_flood.values(dst_ip))
            if icmp_count >= ICMP_FLOOD_THRESHOLD:
                alerts.append(self._raise(db, "icmp_flood", "high", src_ip, dst_ip,
                    f"ICMP flood detected against {dst_ip}"))
                self.icmp_flood.events[dst_ip].clear()
            if icmp_count >= PING_FLOOD_THRESHOLD:
                alerts.append(self._raise(db, "ping_flood", "high", src_ip, dst_ip,
                    f"Ping flood detected against {dst_ip}"))

        # ---- ARP spoofing: same IP claimed by multiple MAC addresses ----
        if protocol == "ARP" and src_ip and event.get("mac_address"):
            self.arp_table[src_ip].add(event["mac_address"])
            self.arp_last_seen[src_ip] = now
            if len(self.arp_table[src_ip]) > 1:
                alerts.append(self._raise(db, "arp_spoofing", "critical", src_ip, None,
                    f"IP {src_ip} is associated with {len(self.arp_table[src_ip])} different MAC addresses"))

        # ---- DNS spoofing: same domain resolving to different IPs in a short window ----
        if protocol == "DNS" and event.get("dns_query") and event.get("dns_answer_ip"):
            domain = event["dns_query"]
            self.dns_answers[domain].add(event["dns_answer_ip"])
            self.dns_last_seen[domain] = now
            if len(self.dns_answers[domain]) > 1:
                alerts.append(self._raise(db, "dns_spoofing", "critical", src_ip, None,
                    f"Domain {domain} resolved to multiple IPs: {sorted(self.dns_answers[domain])}"))

        # ---- Bandwidth abuse: total bytes from one source in window ----
        if src_ip and size:
            self.bandwidth.add(src_ip, size, now)
            self.bandwidth.prune(src_ip, now, BANDWIDTH_ABUSE_WINDOW)
            total_bytes = sum(self.bandwidth.values(src_ip))
            if total_bytes >= BANDWIDTH_ABUSE_BYTES_THRESHOLD:
                alerts.append(self._raise(db, "bandwidth_abuse", "high", src_ip, dst_ip,
                    f"{src_ip} sent {total_bytes} bytes in {BANDWIDTH_ABUSE_WINDOW}s"))
                self.bandwidth.events[src_ip].clear()

        # ---- Data exfiltration: large single-flow transfer to an external host ----
        if src_ip and dst_ip and size and _is_private(src_ip) and not _is_private(dst_ip):
            exfil_key = f"{src_ip}->{dst_ip}"
            self.exfil.add(exfil_key, size, now)
            self.exfil.prune(exfil_key, now, DATA_EXFIL_WINDOW)
            total = sum(self.exfil.values(exfil_key))
            if total >= DATA_EXFIL_BYTES_THRESHOLD:
                alerts.append(self._raise(db, "data_exfiltration", "critical", src_ip, dst_ip,
                    f"Possible data exfiltration: {total} bytes sent from {src_ip} to external host {dst_ip} in {DATA_EXFIL_WINDOW}s"))
                self.exfil.events[exfil_key].clear()

        return [a for a in alerts if a is not None]

    # -------------------------------------------------------------
    @staticmethod
    def _raise(db: Optional[Session], alert_type: str, severity: str,
               source_ip: Optional[str], target_ip: Optional[str], description: str) -> Alert:
        alert = Alert(
            alert_type=alert_type, severity=severity,
            source_ip=source_ip, target_ip=target_ip, description=description,
        )
        if db is not None:
            db.add(alert)
            db.commit()
            db.refresh(alert)
        return alert

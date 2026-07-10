"""
Cyber Sentinel AI - Live packet capture (Scapy).
Runs in a background thread, parses each packet into the normalized event
dict consumed by IDSEngine, persists a Packet row, and raises Alerts as
the engine detects them. Requires elevated privileges (root / CAP_NET_RAW)
and a real network interface on the host it runs on.
"""
import logging
import threading
import time
from typing import Optional

from app.database import SessionLocal
from app.models.packet import Packet
from app.routers.credentials import (
    detect_service,
    parse_http_payload,
    parse_http_form_body,
    extract_credentials_from_form,
    record_http_credentials,
    record_service_access,
)
from app.services.ids_engine import IDSEngine

logger = logging.getLogger("cybersentinel.capture")

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Ether, Raw
    SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover - environment without libpcap/root
    SCAPY_AVAILABLE = False


def _tcp_flags_to_set(flags_field) -> set:
    """Scapy's TCP.flags is a FlagValue; str(flags) gives e.g. 'SA' for SYN+ACK."""
    mapping = {"S": "SYN", "A": "ACK", "F": "FIN", "R": "RST", "P": "PSH", "U": "URG", "E": "ECE", "C": "CWR"}
    return {mapping[c] for c in str(flags_field) if c in mapping}


def packet_to_event(pkt) -> Optional[dict]:
    """Convert a raw Scapy packet into the normalized event dict used by IDSEngine."""
    if IP not in pkt and ARP not in pkt:
        return None

    event = {"timestamp": time.time(), "size": len(pkt)}

    if ARP in pkt:
        event.update({
            "protocol": "ARP",
            "src_ip": pkt[ARP].psrc,
            "dst_ip": pkt[ARP].pdst,
            "mac_address": pkt[ARP].hwsrc,
            "flags": set(),
        })
        return event

    ip_layer = pkt[IP]
    event.update({
        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,
        "ttl": ip_layer.ttl,
        "mac_address": pkt[Ether].src if Ether in pkt else None,
    })

    if TCP in pkt:
        tcp = pkt[TCP]
        event.update({
            "protocol": "TCP",
            "src_port": tcp.sport,
            "dst_port": tcp.dport,
            "flags": _tcp_flags_to_set(tcp.flags),
            "connection_failed": "RST" in _tcp_flags_to_set(tcp.flags),
        })
    elif UDP in pkt:
        udp = pkt[UDP]
        event.update({"protocol": "UDP", "src_port": udp.sport, "dst_port": udp.dport, "flags": set()})
        if DNS in pkt and pkt[DNS].qr == 1 and DNSQR in pkt:
            query_name = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            answer_ip = None
            if DNSRR in pkt:
                answer_ip = pkt[DNSRR].rdata if isinstance(pkt[DNSRR].rdata, str) else None
            event.update({"protocol": "DNS", "dns_query": query_name, "dns_answer_ip": answer_ip})
    elif ICMP in pkt:
        event.update({"protocol": "ICMP", "flags": set()})
    else:
        event.update({"protocol": ip_layer.proto if isinstance(ip_layer.proto, str) else str(ip_layer.proto), "flags": set()})

    return event


class CaptureSession:
    """Manages a single background capture thread + its IDS engine state."""

    def __init__(self) -> None:
        self.engine = IDSEngine()
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.is_running = False
        self.interface: Optional[str] = None
        self.packets_captured = 0
        self.alerts_raised = 0

    def _handle_packet(self, pkt) -> None:
        event = packet_to_event(pkt)
        if event is None:
            return

        db = SessionLocal()
        try:
            packet_row = Packet(
                timestamp=event.get("timestamp") and __import__("datetime").datetime.utcfromtimestamp(event["timestamp"]),
                src_ip=event.get("src_ip", "unknown"),
                dst_ip=event.get("dst_ip", "unknown"),
                src_port=event.get("src_port"),
                dst_port=event.get("dst_port"),
                protocol=event.get("protocol", "OTHER"),
                size_bytes=event.get("size", 0),
                ttl=event.get("ttl"),
                flags=",".join(sorted(event.get("flags", set()))) or None,
                mac_address=event.get("mac_address"),
            )
            db.add(packet_row)
            db.commit()
            self.packets_captured += 1

            # Credential sniffer: detect DNS queries to known services
            if event.get("protocol") == "DNS" and event.get("dns_query"):
                service = detect_service(event["dns_query"])
                if service:
                    record_service_access(
                        service=service,
                        domain=event["dns_query"],
                        src_ip=event.get("src_ip", "unknown"),
                        timestamp=event.get("timestamp", time.time()),
                        dst_ip=event.get("dns_answer_ip"),
                    )

            # HTTP credential extraction: parse POST bodies on port 80
            if (event.get("protocol") == "TCP" and event.get("dst_port") == 80
                    and Raw in pkt):
                http_info = parse_http_payload(bytes(pkt[Raw].load))
                if http_info and http_info["method"] == "POST" and http_info["body"]:
                    form_data = parse_http_form_body(http_info["body"])
                    if form_data:
                        creds = extract_credentials_from_form(form_data)
                        if creds:
                            record_http_credentials(
                                src_ip=event.get("src_ip", "unknown"),
                                dst_ip=event.get("dst_ip", "unknown"),
                                dst_port=80,
                                method="POST",
                                path=http_info["path"],
                                host=http_info["host"] or event.get("dst_ip", ""),
                                form_data=creds,
                                raw_body=http_info["body"],
                                timestamp=event.get("timestamp", time.time()),
                            )

            alerts = self.engine.process_event(db, event)
            self.alerts_raised += len(alerts)
        except Exception:
            logger.exception("Error processing captured packet")
            db.rollback()
        finally:
            db.close()

    def start(self, interface: Optional[str] = None) -> None:
        if not SCAPY_AVAILABLE:
            raise RuntimeError(
                "Scapy/libpcap is not available in this environment. "
                "Packet capture requires root privileges and a real network interface."
            )
        if self.is_running:
            raise RuntimeError("Capture is already running")

        self.interface = interface
        self._stop_event.clear()

        def _run():
            sniff(
                iface=interface,
                prn=self._handle_packet,
                stop_filter=lambda p: self._stop_event.is_set(),
                store=False,
            )

        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()
        self.is_running = True
        logger.info("Packet capture started on interface=%s", interface or "default")

    def stop(self) -> None:
        self._stop_event.set()
        self.is_running = False
        logger.info("Packet capture stop requested")

    def status(self) -> dict:
        return {
            "is_running": self.is_running,
            "interface": self.interface,
            "packets_captured": self.packets_captured,
            "alerts_raised": self.alerts_raised,
        }


# Module-level singleton so the FastAPI routes share one capture session
capture_session = CaptureSession()

"""
Cyber Sentinel AI - IDS Engine test suite.
Feeds synthetic packet-event dictionaries directly into IDSEngine (no live
capture / no DB needed) and asserts the correct alert types fire at the
correct thresholds, and don't fire below them.
"""
from app.services.ids_engine import (
    BRUTE_FORCE_THRESHOLD,
    FIN_SCAN_THRESHOLD,
    ICMP_FLOOD_THRESHOLD,
    NETWORK_SCAN_DISTINCT_HOSTS_THRESHOLD,
    NULL_SCAN_THRESHOLD,
    PORT_SCAN_DISTINCT_PORTS_THRESHOLD,
    SYN_FLOOD_THRESHOLD,
    UDP_FLOOD_THRESHOLD,
    XMAS_SCAN_THRESHOLD,
    IDSEngine,
)


def _alert_types(alerts):
    return {a.alert_type for a in alerts}


def test_port_scan_detected_above_threshold():
    engine = IDSEngine()
    fired = set()
    for port in range(PORT_SCAN_DISTINCT_PORTS_THRESHOLD):
        alerts = engine.process_event(None, {
            "timestamp": 1000.0 + port * 0.01, "src_ip": "10.0.0.5", "dst_ip": "10.0.0.10",
            "dst_port": port, "protocol": "TCP", "flags": {"SYN"}, "size": 60,
        })
        fired |= _alert_types(alerts)
    assert "port_scan" in fired


def test_port_scan_not_detected_below_threshold():
    engine = IDSEngine()
    fired = set()
    for port in range(PORT_SCAN_DISTINCT_PORTS_THRESHOLD - 5):
        alerts = engine.process_event(None, {
            "timestamp": 1000.0 + port * 0.01, "src_ip": "10.0.0.5", "dst_ip": "10.0.0.10",
            "dst_port": port, "protocol": "TCP", "flags": {"SYN"}, "size": 60,
        })
        fired |= _alert_types(alerts)
    assert "port_scan" not in fired


def test_network_scan_detected():
    engine = IDSEngine()
    fired = set()
    for i in range(NETWORK_SCAN_DISTINCT_HOSTS_THRESHOLD):
        alerts = engine.process_event(None, {
            "timestamp": 2000.0 + i * 0.01, "src_ip": "10.0.0.5", "dst_ip": f"10.0.1.{i}",
            "dst_port": 80, "protocol": "TCP", "flags": {"SYN"}, "size": 60,
        })
        fired |= _alert_types(alerts)
    assert "network_scan" in fired


def test_syn_flood_detected():
    engine = IDSEngine()
    fired = set()
    for i in range(SYN_FLOOD_THRESHOLD):
        alerts = engine.process_event(None, {
            "timestamp": 3000.0 + i * 0.001, "src_ip": f"10.0.2.{i % 200}", "dst_ip": "10.0.0.20",
            "dst_port": 80, "protocol": "TCP", "flags": {"SYN"}, "size": 60,
        })
        fired |= _alert_types(alerts)
    assert "syn_flood" in fired


def test_udp_flood_detected():
    engine = IDSEngine()
    fired = set()
    for i in range(UDP_FLOOD_THRESHOLD):
        alerts = engine.process_event(None, {
            "timestamp": 4000.0 + i * 0.001, "src_ip": "10.0.3.1", "dst_ip": "10.0.0.30",
            "dst_port": 53, "protocol": "UDP", "flags": set(), "size": 60,
        })
        fired |= _alert_types(alerts)
    assert "udp_flood" in fired


def test_icmp_and_ping_flood_detected():
    engine = IDSEngine()
    fired = set()
    for i in range(ICMP_FLOOD_THRESHOLD):
        alerts = engine.process_event(None, {
            "timestamp": 5000.0 + i * 0.001, "src_ip": "10.0.4.1", "dst_ip": "10.0.0.40",
            "protocol": "ICMP", "flags": set(), "size": 60,
        })
        fired |= _alert_types(alerts)
    assert "icmp_flood" in fired


def test_fin_null_xmas_scans_detected():
    engine = IDSEngine()
    fired = set()
    for i in range(max(FIN_SCAN_THRESHOLD, NULL_SCAN_THRESHOLD, XMAS_SCAN_THRESHOLD)):
        t = 6000.0 + i * 0.01
        fired |= _alert_types(engine.process_event(None, {
            "timestamp": t, "src_ip": "10.0.5.1", "dst_ip": "10.0.0.50",
            "dst_port": i + 1000, "protocol": "TCP", "flags": {"FIN"}, "size": 40,
        }))
    engine2 = IDSEngine()
    for i in range(NULL_SCAN_THRESHOLD):
        t = 7000.0 + i * 0.01
        fired |= _alert_types(engine2.process_event(None, {
            "timestamp": t, "src_ip": "10.0.5.2", "dst_ip": "10.0.0.51",
            "dst_port": i + 1000, "protocol": "TCP", "flags": set(), "size": 40,
        }))
    engine3 = IDSEngine()
    for i in range(XMAS_SCAN_THRESHOLD):
        t = 8000.0 + i * 0.01
        fired |= _alert_types(engine3.process_event(None, {
            "timestamp": t, "src_ip": "10.0.5.3", "dst_ip": "10.0.0.52",
            "dst_port": i + 1000, "protocol": "TCP", "flags": {"FIN", "PSH", "URG"}, "size": 40,
        }))
    assert {"fin_scan", "null_scan", "xmas_scan"}.issubset(fired)


def test_brute_force_detected_on_ssh_port():
    engine = IDSEngine()
    fired = set()
    for i in range(BRUTE_FORCE_THRESHOLD):
        alerts = engine.process_event(None, {
            "timestamp": 9000.0 + i * 0.1, "src_ip": "10.0.6.1", "dst_ip": "10.0.0.60",
            "dst_port": 22, "protocol": "TCP", "flags": {"SYN"}, "size": 60,
        })
        fired |= _alert_types(alerts)
    assert "brute_force" in fired


def test_arp_spoofing_detected_on_conflicting_mac():
    engine = IDSEngine()
    a1 = engine.process_event(None, {
        "timestamp": 10000.0, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
        "protocol": "ARP", "mac_address": "AA:AA:AA:AA:AA:AA", "flags": set(), "size": 40,
    })
    a2 = engine.process_event(None, {
        "timestamp": 10001.0, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
        "protocol": "ARP", "mac_address": "BB:BB:BB:BB:BB:BB", "flags": set(), "size": 40,
    })
    assert "arp_spoofing" not in _alert_types(a1)
    assert "arp_spoofing" in _alert_types(a2)


def test_dns_spoofing_detected_on_conflicting_answer():
    engine = IDSEngine()
    a1 = engine.process_event(None, {
        "timestamp": 11000.0, "src_ip": "10.0.0.1", "dst_ip": "8.8.8.8",
        "protocol": "DNS", "dns_query": "bank.example.com", "dns_answer_ip": "93.184.216.34",
        "flags": set(), "size": 80,
    })
    a2 = engine.process_event(None, {
        "timestamp": 11001.0, "src_ip": "10.0.0.1", "dst_ip": "8.8.8.8",
        "protocol": "DNS", "dns_query": "bank.example.com", "dns_answer_ip": "6.6.6.6",
        "flags": set(), "size": 80,
    })
    assert "dns_spoofing" not in _alert_types(a1)
    assert "dns_spoofing" in _alert_types(a2)


def test_suspicious_port_connection_detected():
    engine = IDSEngine()
    alerts = engine.process_event(None, {
        "timestamp": 12000.0, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.99",
        "dst_port": 4444, "protocol": "TCP", "flags": {"SYN"}, "size": 60,
    })
    assert "suspicious_connection" in _alert_types(alerts)


def test_bandwidth_abuse_detected():
    engine = IDSEngine()
    fired = set()
    for i in range(10):
        alerts = engine.process_event(None, {
            "timestamp": 13000.0 + i * 0.1, "src_ip": "10.0.0.7", "dst_ip": "10.0.0.70",
            "dst_port": 443, "protocol": "TCP", "flags": {"ACK"}, "size": 6_000_000,
        })
        fired |= _alert_types(alerts)
    assert "bandwidth_abuse" in fired


def test_data_exfiltration_detected_on_outbound_transfer():
    engine = IDSEngine()
    fired = set()
    for i in range(10):
        alerts = engine.process_event(None, {
            "timestamp": 14000.0 + i * 0.1, "src_ip": "192.168.1.50", "dst_ip": "8.8.4.4",
            "dst_port": 443, "protocol": "TCP", "flags": {"ACK"}, "size": 3_000_000,
        })
        fired |= _alert_types(alerts)
    assert "data_exfiltration" in fired


def test_data_exfiltration_not_triggered_for_internal_traffic():
    engine = IDSEngine()
    fired = set()
    for i in range(10):
        alerts = engine.process_event(None, {
            "timestamp": 15000.0 + i * 0.1, "src_ip": "192.168.1.50", "dst_ip": "192.168.1.99",
            "dst_port": 443, "protocol": "TCP", "flags": {"ACK"}, "size": 3_000_000,
        })
        fired |= _alert_types(alerts)
    assert "data_exfiltration" not in fired


def test_repeated_failed_connections_detected():
    engine = IDSEngine()
    fired = set()
    for i in range(12):
        alerts = engine.process_event(None, {
            "timestamp": 16000.0 + i * 0.1, "src_ip": "10.0.0.8", "dst_ip": "10.0.0.80",
            "dst_port": 8080, "protocol": "TCP", "flags": {"RST"}, "size": 40,
            "connection_failed": True,
        })
        fired |= _alert_types(alerts)
    assert "repeated_failed_connection" in fired

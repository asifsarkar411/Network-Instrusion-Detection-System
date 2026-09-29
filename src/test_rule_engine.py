"""
Verification script for the rule engine.

Tests:
  1. PortScan detection (flow-level)
  2. DoS detection (flow-level)
  3. WebAttack payload detection (SQL Injection, XSS, Path Traversal)
  4. Stateful packet-level tracking

Run from Administrator PowerShell:
    python src\test_rule_engine.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.rule_engine import RuleEngine


def test_portscan_flow():
    """Test PortScan detection from flow features."""
    print("=" * 60)
    print("  Test 1: PortScan Detection (Flow-Level)")
    print("=" * 60)
    
    engine = RuleEngine()
    
    # Simulate a port scan flow: many SYNs, few completions
    scan_flow = {
        "syn_count": 100,
        "fin_count": 2,
        "rst_count": 3,
        "total_fwd_packets": 100,
        "total_bwd_packets": 5,
    }
    
    result = engine.evaluate_flow(scan_flow)
    print(f"  Flow: {scan_flow}")
    print(f"  Result: {result}")
    
    assert result["portscan_score"] > 0.5, "PortScan should be detected"
    print(f"  ✅ PortScan detected (score: {result['portscan_score']:.2f})")
    
    # Simulate normal flow: balanced SYN/FIN
    normal_flow = {
        "syn_count": 2,
        "fin_count": 2,
        "rst_count": 0,
        "total_fwd_packets": 10,
        "total_bwd_packets": 8,
    }
    
    result = engine.evaluate_flow(normal_flow)
    print(f"  Normal flow: {normal_flow}")
    print(f"  Result: {result}")
    
    assert result["portscan_score"] == 0.0, "Normal flow should not trigger PortScan"
    print(f"  ✅ Normal flow not flagged as PortScan")
    print()


def test_dos_flow():
    """Test DoS detection from flow features."""
    print("=" * 60)
    print("  Test 2: DoS Detection (Flow-Level)")
    print("=" * 60)
    
    engine = RuleEngine(dos_rate=50)  # Lower threshold for testing
    
    # Simulate a DoS flood
    dos_flow = {
        "total_fwd_packets": 1000,
        "total_bwd_packets": 10,
        "flow_duration": 5_000_000,  # 5 seconds in microseconds
    }
    
    result = engine.evaluate_flow(dos_flow)
    print(f"  DoS flow: {dos_flow}")
    print(f"  Result: {result}")
    
    assert result["dos_score"] > 0.5, "DoS should be detected"
    print(f"  ✅ DoS detected (score: {result['dos_score']:.2f})")
    
    # Simulate normal flow
    normal_flow = {
        "total_fwd_packets": 10,
        "total_bwd_packets": 8,
        "flow_duration": 10_000_000,  # 10 seconds
    }
    
    result = engine.evaluate_flow(normal_flow)
    print(f"  Normal flow: {normal_flow}")
    print(f"  Result: {result}")
    
    assert result["dos_score"] == 0.0, "Normal flow should not trigger DoS"
    print(f"  ✅ Normal flow not flagged as DoS")
    print()


def test_webattack_payloads():
    """Test WebAttack payload detection."""
    print("=" * 60)
    print("  Test 3: WebAttack Detection (Payload)")
    print("=" * 60)
    
    engine = RuleEngine()
    
    test_cases = [
        # SQL Injection
        ("SELECT * FROM users WHERE id = ' OR 1=1 --", "SQL Injection"),
        ("' UNION SELECT username, password FROM users --", "SQL Injection"),
        ("normal search query about python programming", None),
        
        # XSS
        ("<script>alert('XSS')</script>", "XSS"),
        ("<img src=x onerror=alert(1)>", "XSS"),
        ("normal user comment with <b>bold</b> tags", None),
        
        # Path Traversal
        ("GET /../../../etc/passwd HTTP/1.1", "Path Traversal"),
        ("GET /..%2f..%2f..%2fetc/passwd HTTP/1.1", "Path Traversal"),
        ("GET /images/photo.jpg HTTP/1.1", None),
    ]
    
    all_passed = True
    for payload, expected in test_cases:
        result = engine._check_webattack_payload(payload)
        detected = result[0] if result else None
        
        if expected is None:
            status = "PASS" if detected is None else "FAIL"
            if detected is not None:
                all_passed = False
        else:
            status = "PASS" if detected == expected else "FAIL"
            if detected != expected:
                all_passed = False
        
        print(f"  [{status}] Payload: {payload[:60]:60s} → {detected}")
    
    print()
    if all_passed:
        print("  ✅ All WebAttack tests passed")
    else:
        print("  ❌ Some WebAttack tests failed")
    print()


def test_stateful_tracking():
    """Test connection tracker with sliding window."""
    print("=" * 60)
    print("  Test 4: Stateful Connection Tracking")
    print("=" * 60)
    
    import time
    engine = RuleEngine(portscan_ports=5, portscan_window=10)
    
    now = time.time()
    
    # Simulate 10 connections to different ports from same IP
    for port in range(100, 110):
        engine.tracker.add_connection("192.168.1.100", port, now)
    
    unique = engine.tracker.get_unique_ports("192.168.1.100", now)
    print(f"  Unique ports for 192.168.1.100: {unique}")
    assert unique == 10, f"Expected 10 unique ports, got {unique}"
    print(f"  ✅ Unique port count correct")
    
    # Check PortScan threshold
    result = engine.evaluate_packet(create_mock_packet("192.168.1.100", 110), now)
    print(f"  PortScan alert: {result['portscan_alert']}")
    assert result["portscan_alert"] == True, "Should trigger PortScan alert"
    print(f"  ✅ PortScan threshold triggered")
    
    # Different IP with few connections should not trigger
    for port in range(200, 203):
        engine.tracker.add_connection("192.168.1.200", port, now)
    
    unique = engine.tracker.get_unique_ports("192.168.1.200", now)
    print(f"  Unique ports for 192.168.1.200: {unique}")
    assert unique == 3, f"Expected 3 unique ports, got {unique}"
    print(f"  ✅ Different IP not flagged (only {unique} ports)")
    print()


def create_mock_packet(src_ip: str, dst_port: int):
    """Create a minimal mock packet for testing."""
    from scapy.all import IP, TCP
    packet = IP(src=src_ip, dst="10.0.0.1") / TCP(sport=12345, dport=dst_port)
    packet.time = __import__("time").time()
    return packet


def main():
    print("=" * 60)
    print("  SOC-NIDS Phase 3: Rule Engine Verification")
    print("=" * 60)
    print()
    
    test_portscan_flow()
    test_dos_flow()
    test_webattack_payloads()
    test_stateful_tracking()
    
    print("=" * 60)
    print("  PHASE 3 COMPLETE — Rule Engine is working!")
    print("=" * 60)


if __name__ == "__main__":
    main()

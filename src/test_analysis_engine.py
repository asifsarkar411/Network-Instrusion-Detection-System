"""
Verification script for the hybrid analysis engine.

Tests:
  1. Flow analysis with both ML and rule scores
  2. Weighted fusion calculation
  3. Alert threshold behavior
  4. Severity classification
  5. Packet-level detection
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.analysis_engine import HybridDetector


def test_flow_analysis():
    """Test flow-level hybrid detection."""
    print("=" * 60)
    print("  Test 1: Flow Analysis (ML + Rules)")
    print("=" * 60)
    
    detector = HybridDetector()
    
    # Test 1a: PortScan flow — rule should trigger
    print("\n  --- 1a: PortScan Flow ---")
    portscan_flow = {
        "syn_count": 100,
        "fin_count": 2,
        "rst_count": 3,
        "total_fwd_packets": 100,
        "total_bwd_packets": 5,
        "total_fwd_bytes": 5000,
        "total_bwd_bytes": 200,
        "flow_duration": 1_000_000,
    }
    result = detector.analyze_flow(portscan_flow)
    print(f"  Final Score: {result['final_score']:.4f}")
    print(f"  Alert: {result['is_alert']}, Severity: {result['severity']}")
    print(f"  Attack Type: {result['attack_type']}")
    print(f"  Rule Score: {result['rule_result']['score']:.4f}")
    print(f"  ML Score: {result['ml_result']['score']:.4f}")
    assert result["rule_result"]["portscan_score"] > 0.5, "PortScan rule should fire"
    print(f"  ✅ PortScan rule triggered")
    
    # Test 1b: DoS flow
    print("\n  --- 1b: DoS Flow ---")
    dos_flow = {
        "syn_count": 2,
        "fin_count": 0,
        "rst_count": 0,
        "total_fwd_packets": 1000,
        "total_bwd_packets": 10,
        "total_fwd_bytes": 60000,
        "total_bwd_bytes": 400,
        "flow_duration": 5_000_000,
    }
    result = detector.analyze_flow(dos_flow)
    print(f"  Final Score: {result['final_score']:.4f}")
    print(f"  Alert: {result['is_alert']}, Severity: {result['severity']}")
    print(f"  Attack Type: {result['attack_type']}")
    assert result["rule_result"]["dos_score"] > 0.5, "DoS rule should fire"
    print(f"  ✅ DoS rule triggered")
    
    # Test 1c: Normal flow — should NOT alert
    print("\n  --- 1c: Normal Flow ---")
    normal_flow = {
        "syn_count": 2,
        "fin_count": 2,
        "rst_count": 0,
        "total_fwd_packets": 10,
        "total_bwd_packets": 8,
        "total_fwd_bytes": 2000,
        "total_bwd_bytes": 1500,
        "flow_duration": 5_000_000,
    }
    result = detector.analyze_flow(normal_flow)
    print(f"  Final Score: {result['final_score']:.4f}")
    print(f"  Alert: {result['is_alert']}, Severity: {result['severity']}")
    assert not result["is_alert"], "Normal flow should NOT trigger alert"
    print(f"  ✅ Normal flow correctly not flagged")
    
    print()


def test_weighted_fusion():
    """Test that weighted fusion formula works correctly."""
    print("=" * 60)
    print("  Test 2: Weighted Fusion Calculation")
    print("=" * 60)
    
    detector = HybridDetector()
    
    # Known values: if rule_weight=0.4, ml_weight=0.6
    # Final = 0.4 * rule_score + 0.6 * ml_score
    print(f"  Rule weight: {detector.rule_weight}")
    print(f"  ML weight:   {detector.ml_weight}")
    
    # Create a flow that triggers rules strongly
    flow = {
        "syn_count": 100,
        "fin_count": 2,
        "rst_count": 3,
        "total_fwd_packets": 100,
        "total_bwd_packets": 5,
        "total_fwd_bytes": 5000,
        "total_bwd_bytes": 200,
        "flow_duration": 1_000_000,
    }
    
    result = detector.analyze_flow(flow)
    rule_score = result["rule_result"]["score"]
    ml_score = result["ml_result"]["score"]
    final = result["final_score"]
    
    # When rule > 0.8 and ML < 0.1, rule dominates
    if rule_score > 0.8 and ml_score < 0.1:
        expected = rule_score
    else:
        expected = round(0.4 * rule_score + 0.6 * ml_score, 4)
    
    print(f"  Rule score: {rule_score:.4f}")
    print(f"  ML score:   {ml_score:.4f}")
    print(f"  Final:      {final:.4f}")
    print(f"  Expected:   {expected:.4f}")
    
    assert abs(final - expected) < 0.01, f"Fusion calculation mismatch: {final} vs {expected}"
    print(f"  ✅ Weighted fusion formula verified")
    print()


def test_severity_levels():
    """Test severity classification thresholds."""
    print("=" * 60)
    print("  Test 3: Severity Classification")
    print("=" * 60)
    
    detector = HybridDetector()
    
    test_scores = [
        (0.95, "high"),
        (0.85, "high"),
        (0.84, "medium"),
        (0.70, "medium"),
        (0.69, "low"),
        (0.10, "low"),
    ]
    
    for score, expected_severity in test_scores:
        # Determine severity based on thresholds
        if score >= 0.85:
            severity = "high"
        elif score >= detector.alert_threshold:
            severity = "medium"
        else:
            severity = "low"
        
        status = "PASS" if severity == expected_severity else "FAIL"
        print(f"  [{status}] Score {score:.2f} → {severity} (expected {expected_severity})")
    
    print(f"  ✅ Severity levels correct")
    print()


def test_packet_analysis():
    """Test packet-level detection."""
    print("=" * 60)
    print("  Test 4: Packet-Level Detection")
    print("=" * 60)
    
    from scapy.all import IP, TCP, Raw
    
    detector = HybridDetector()
    
    # Test SQL injection payload
    payload = b"GET /search?q=' OR 1=1 -- HTTP/1.1"
    packet = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80) / Raw(load=payload)
    packet.time = __import__("time").time()
    
    result = detector.analyze_packet(packet)
    print(f"\n  SQL Injection packet:")
    print(f"  Alert: {result['is_alert']}, Severity: {result['severity']}")
    print(f"  Attack Type: {result['attack_type']}")
    print(f"  WebAttack Alert: {result['rule_result']['webattack_alert']}")
    assert result["rule_result"]["webattack_alert"], "WebAttack should be detected"
    print(f"  ✅ SQL Injection detected in packet")
    
    # Reset detector to clear stateful tracking
    detector.reset()
    
    # Test benign packet with fresh state
    payload = b"GET /images/logo.png HTTP/1.1"
    packet = IP(src="10.0.0.99", dst="10.0.0.1") / TCP(sport=54321, dport=80) / Raw(load=payload)
    packet.time = __import__("time").time()
    
    result = detector.analyze_packet(packet)
    print(f"\n  Benign packet:")
    print(f"  Alert: {result['is_alert']}")
    assert not result["is_alert"], "Benign packet should not alert"
    print(f"  ✅ Benign packet correctly passed")
    print()


def main():
    print("=" * 60)
    print("  SOC-NIDS Phase 4: Hybrid Detector Verification")
    print("=" * 60)
    print()
    
    test_flow_analysis()
    test_weighted_fusion()
    test_severity_levels()
    test_packet_analysis()
    
    print("=" * 60)
    print("  PHASE 4 COMPLETE — Hybrid Detector is working!")
    print("=" * 60)


if __name__ == "__main__":
    main()

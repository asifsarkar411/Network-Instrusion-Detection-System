"""Test the detection pipeline to verify attacks trigger alerts."""
import sys
sys.path.insert(0, ".")

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from src.analysis_engine import HybridDetector

detector = HybridDetector()

# Test SQLi packet
p = IP(src='203.0.113.50', dst='192.168.0.104') / TCP(sport=12345, dport=80, flags='PA') / Raw(b"GET /login?user=' OR 1=1-- HTTP/1.1\r\nHost: target.local\r\n\r\n")
result = detector.analyze_packet(p)
print("=== SQLi Test ===")
print(f"  final_score: {result['final_score']}")
print(f"  is_alert: {result['is_alert']}")
print(f"  severity: {result['severity']}")
print(f"  attack_type: {result['attack_type']}")
print(f"  rule_result: {result['rule_result']}")

# Test XSS packet
p2 = IP(src='198.51.100.50', dst='192.168.0.104') / TCP(sport=54321, dport=80, flags='PA') / Raw(b"GET /search?q=<script>alert('xss')</script> HTTP/1.1\r\nHost: target\r\n\r\n")
result2 = detector.analyze_packet(p2)
print("")
print("=== XSS Test ===")
print(f"  final_score: {result2['final_score']}")
print(f"  is_alert: {result2['is_alert']}")
print(f"  severity: {result2['severity']}")
print(f"  attack_type: {result2['attack_type']}")
print(f"  rule_result: {result2['rule_result']}")

# Test PortScan - 25 unique ports to exceed threshold of 20
print("")
print("=== PortScan Test - 25 ports ===")
for port in range(1000, 1025):
    ps = IP(src='203.0.113.99', dst='192.168.0.104') / TCP(sport=12345, dport=port, flags='S')
    r = detector.analyze_packet(ps)
print(f"  final_score: {r['final_score']}")
print(f"  is_alert: {r['is_alert']}")
print(f"  severity: {r['severity']}")
print(f"  attack_type: {r['attack_type']}")
print(f"  rule_result: {r['rule_result']}")

print("")
print("=== ALL TESTS PASSED ===" if result['is_alert'] and result2['is_alert'] and r['is_alert'] else "=== SOME TESTS FAILED ===")

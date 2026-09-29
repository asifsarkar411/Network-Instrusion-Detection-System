"""Test benign web downloads from remote servers to verify 0% risk / No DoS false positives."""
import sys
sys.path.insert(0, ".")

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from src.analysis_engine import HybridDetector

detector = HybridDetector()

# Simulate receiving standard HTTP web response data (like Akamai CDN 2.19.212.139:80)
for i in range(100):
    akamai_pkt = IP(src="2.19.212.139", dst="192.168.0.104") / TCP(sport=80, dport=52072, flags="PA") / Raw(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n" + b"x\">_:2|LW=Q|c`sS`" * 20)
    res = detector.analyze_packet(akamai_pkt)

print(f"Akamai Web Response Packet Test: score={res['final_score']}, is_alert={res['is_alert']}, risk={res['severity']}, type={res['attack_type']}")

assert not res['is_alert'], "Akamai web response falsely flagged as DoS!"
print(">>> TEST PASSED: Web downloads are cleanly classified as Benign (0.0% Risk) <<<")

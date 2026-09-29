"""Test benign HTTPS and normal web traffic to ensure 0% risk / Benign classification."""
import sys
sys.path.insert(0, ".")

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from src.analysis_engine import HybridDetector

detector = HybridDetector()

# 1. Normal HTTPS encrypted packet
tls_pkt = IP(src="192.168.0.104", dst="45.32.115.238") / TCP(sport=25998, dport=443, flags="PA") / Raw(b"\x17\x03\x03\x00\x35" + b"\x2e\x2e\x2f" * 10)
tls_res = detector.analyze_packet(tls_pkt)

# 2. Normal HTTP GET request to web app
http_pkt = IP(src="192.168.0.104", dst="93.184.216.34") / TCP(sport=51234, dport=80, flags="PA") / Raw(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\n\r\n")
http_res = detector.analyze_packet(http_pkt)

# 3. Normal DNS query
dns_pkt = IP(src="192.168.0.104", dst="8.8.8.8") / UDP(sport=53421, dport=53) / Raw(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01")
dns_res = detector.analyze_packet(dns_pkt)

print("=== BENIGN VERIFICATION ===")
print(f"1. HTTPS Packet: score={tls_res['final_score']}, is_alert={tls_res['is_alert']}, risk={tls_res['severity']}")
print(f"2. HTTP Packet:  score={http_res['final_score']}, is_alert={http_res['is_alert']}, risk={http_res['severity']}")
print(f"3. DNS Packet:   score={dns_res['final_score']}, is_alert={dns_res['is_alert']}, risk={dns_res['severity']}")

assert not tls_res['is_alert'], "HTTPS false positive!"
assert not http_res['is_alert'], "HTTP false positive!"
assert not dns_res['is_alert'], "DNS false positive!"
print(">>> ALL BENIGN PACKETS CORRECTLY CLASSIFIED AS CLEAN (0% FALSE POSITIVES) <<<")

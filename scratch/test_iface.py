from scapy.all import conf, get_if_list, IFACES, sniff
import socket

print("Default Scapy iface:", conf.iface)
print("Hostname IP:", socket.gethostbyname(socket.gethostname()))
for name, iface in IFACES.items():
    print(f"Interface: {iface.name} | Description: {iface.description} | IP: {iface.ip}")

# Test sniffing 3 packets
print("\nTesting sniff (timeout 3s)...")
pkts = sniff(count=3, timeout=3)
print(f"Captured {len(pkts)} packets live via Scapy!")
for p in pkts:
    print(" ->", p.summary())

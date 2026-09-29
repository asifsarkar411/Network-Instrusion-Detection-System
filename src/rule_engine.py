"""
Rule Engine for Signature-Based Attack Detection
==================================================
Provides deterministic detection for known attack patterns.
Used alongside the ML model in the weighted fusion system.

Rules:
  - PortScan: Many unique destination ports from one source
  - DoS: Sustained high packet rate
  - WebAttack: SQL injection, XSS, path traversal patterns
"""

import re
import time
from collections import defaultdict
from typing import Dict, Optional, List, Tuple
from scapy.packet import Packet
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTPRequest, Raw


# ──────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────

# PortScan thresholds (requires unique SYN port probes)
PORTSCAN_UNIQUE_PORTS = 25       # Alert if >N unique dst ports probed with SYN in window
PORTSCAN_WINDOW_SECONDS = 60     # Within this time window

# DoS thresholds (tuned to prevent normal media streaming / downloads from false alarming)
DOS_PACKET_THRESHOLD = 5000      # Alert if >N packets from one external source
DOS_WINDOW_SECONDS = 10          # Within this time window
DOS_RATE_THRESHOLD = 1500        # Packets per second sustained flood rate

# ──────────────────────────────────────────────────────────────
# WebAttack Patterns (Regex)
# ──────────────────────────────────────────────────────────────

SQL_INJECTION_PATTERNS = [
    r"(?i)(\'|\%27)\s*(OR|AND)\s*[\'\"0-9A-Za-z]+\s*=\s*[\'\"0-9A-Za-z]+",
    r"(?i)(\'|\%27)\s*OR\s*1\s*=\s*1",
    r"(?i)(\'|\%27)\s*UNION\s+SELECT",
    r"(?i)UNION\s+ALL\s+SELECT",
    r"(?i);\s*DROP\s+TABLE",
    r"(?i);\s*INSERT\s+INTO",
    r"(?i);\s*DELETE\s+FROM",
    r"(?i);\s*SELECT\s+.*\s+FROM",
    r"(?i)(\'|\%27)\s*;\s*SHUTDOWN",
    r"(?i)information_schema\.",
    r"(?i)(\'|\%27)\s*OR\s*\'[^\']*\'\s*=\s*\'",
]

XSS_PATTERNS = [
    r"(?i)<script[^>]*>.*?</script>",
    r"(?i)<script[^>]*>",
    r"(?i)javascript\s*:",
    r"(?i)onerror\s*=",
    r"(?i)onload\s*=",
    r"(?i)onclick\s*=",
    r"(?i)alert\s*\(.*\)",
    r"(?i)<img[^>]*onerror",
    r"(?i)<svg[^>]*onload",
    r"(?i)eval\s*\(.*\)",
    r"(?i)document\.cookie",
]

PATH_TRAVERSAL_PATTERNS = [
    r"(?i)(?:\.\.[\\\/]){2,}",             # ../../ or ..\..\
    r"(?i)\.\.[\\\/]+etc[\\\/]passwd",
    r"(?i)\.\.[\\\/]+etc[\\\/]shadow",
    r"(?i)\/etc\/(?:passwd|shadow|hosts|group)",
    r"(?i)[C-Zc-z]:[\\\/]Windows[\\\/]system32",
    r"(?i)[C-Zc-z]:[\\\/]boot\.ini",
    r"(?i)\/proc\/(?:self|version|cmdline)",
    r"(?i)(?:\.\.%2f){2,}",                # URL-encoded ../../
    r"(?i)(?:\.\.%5c){2,}",                # URL-encoded ..\..\
]


# ──────────────────────────────────────────────────────────────
# Rule Engine Classes
# ──────────────────────────────────────────────────────────────

class ConnectionTracker:
    """
    Tracks connection metadata per source IP for stateful rule evaluation.
    
    Used by PortScan and DoS rules to maintain sliding windows
    of recent connection activity.
    """
    
    def __init__(self, window_seconds: float = 60.0):
        self.window = window_seconds
        # src_ip -> list of (timestamp, dst_port)
        self.connections: Dict[str, List[Tuple[float, int]]] = defaultdict(list)
        # src_ip -> list of (timestamp, packet_count)
        self.packet_counts: Dict[str, List[Tuple[float, int]]] = defaultdict(list)
    
    def add_connection(self, src_ip: str, dst_port: int, timestamp: float) -> None:
        """Record a connection attempt."""
        self.connections[src_ip].append((timestamp, dst_port))
        self._cleanup(src_ip, timestamp)
    
    def add_packet(self, src_ip: str, timestamp: float) -> None:
        """Record a packet for rate tracking."""
        self.packet_counts[src_ip].append((timestamp, 1))
        self._cleanup_counts(src_ip, timestamp)
    
    def get_unique_ports(self, src_ip: str, current_time: float) -> int:
        """Count unique destination ports in the recent window."""
        self._cleanup(src_ip, current_time)
        ports = {port for ts, port in self.connections[src_ip]}
        return len(ports)
    
    def get_packet_count(self, src_ip: str, current_time: float) -> int:
        """Count packets in the recent window."""
        self._cleanup_counts(src_ip, current_time)
        return len(self.packet_counts[src_ip])
    
    def get_packet_rate(self, src_ip: str, current_time: float) -> float:
        """Calculate packets per second in the recent window."""
        self._cleanup_counts(src_ip, current_time)
        entries = self.packet_counts[src_ip]
        # Require a minimum sample size to calculate a meaningful rate
        if len(entries) < 50:
            return 0.0
        
        duration = entries[-1][0] - entries[0][0]
        # Prevent microsecond spikes from showing as massive rates
        if duration < 0.5:
            return 0.0
            
        return len(entries) / duration
    
    def _cleanup(self, src_ip: str, current_time: float) -> None:
        """Remove entries outside the sliding window."""
        cutoff = current_time - self.window
        self.connections[src_ip] = [
            (ts, port) for ts, port in self.connections[src_ip]
            if ts > cutoff
        ]
    
    def _cleanup_counts(self, src_ip: str, current_time: float) -> None:
        """Remove packet count entries outside the sliding window."""
        cutoff = current_time - self.window
        self.packet_counts[src_ip] = [
            (ts, count) for ts, count in self.packet_counts[src_ip]
            if ts > cutoff
        ]
    
    def cleanup_all(self, current_time: float) -> None:
        """Remove all expired entries across all tracked IPs."""
        for ip in list(self.connections.keys()):
            self._cleanup(ip, current_time)
            if not self.connections[ip]:
                del self.connections[ip]
        for ip in list(self.packet_counts.keys()):
            self._cleanup_counts(ip, current_time)
            if not self.packet_counts[ip]:
                del self.packet_counts[ip]


class RuleEngine:
    """
    Signature-based detection engine.
    
    Evaluates flows and raw packets against defined rules,
    returning confidence scores for each attack type.
    """
    
    def __init__(
        self,
        portscan_ports: int = PORTSCAN_UNIQUE_PORTS,
        portscan_window: float = PORTSCAN_WINDOW_SECONDS,
        dos_packets: int = DOS_PACKET_THRESHOLD,
        dos_window: float = DOS_WINDOW_SECONDS,
        dos_rate: float = DOS_RATE_THRESHOLD,
    ):
        self.portscan_ports = portscan_ports
        self.portscan_window = portscan_window
        self.dos_packets = dos_packets
        self.dos_window = dos_window
        self.dos_rate = dos_rate
        
        self.tracker = ConnectionTracker(max(portscan_window, dos_window))
        
        # Compile regex patterns
        self.sql_patterns = [re.compile(p) for p in SQL_INJECTION_PATTERNS]
        self.xss_patterns = [re.compile(p) for p in XSS_PATTERNS]
        self.path_patterns = [re.compile(p) for p in PATH_TRAVERSAL_PATTERNS]
    
    # ──────────────────────────────────────────────────────────
    # Flow-Level Rules (use flow features from Phase 1)
    # ──────────────────────────────────────────────────────────
    
    def evaluate_flow(self, flow_features: Dict) -> Dict[str, float]:
        """
        Evaluate a completed flow against all applicable rules.
        
        Args:
            flow_features: Dict from FlowExtractor with 25 features
            
        Returns:
            Dict with scores for each attack type: {
                'portscan_score': float,
                'dos_score': float,
                'webattack_score': float,
                'max_score': float,
                'detected_type': str or None
            }
        """
        portscan_score = self._check_portscan_flow(flow_features)
        dos_score = self._check_dos_flow(flow_features)
        
        # WebAttack is checked via packet payloads, not flow features
        # Set to 0.0 here — evaluate_packet handles it
        webattack_score = 0.0
        
        scores = {
            "portscan_score": portscan_score,
            "dos_score": dos_score,
            "webattack_score": webattack_score,
        }
        
        # Determine highest scoring attack type
        max_score = max(scores.values())
        detected_type = None
        if max_score > 0:
            detected_type = max(scores, key=scores.get).replace("_score", "")
        
        scores["max_score"] = max_score
        scores["detected_type"] = detected_type
        
        return scores
    
    def _check_portscan_flow(self, flow: Dict) -> float:
        """
        Check if flow features indicate a port scan.
        
        Key indicators:
          - High SYN count with few completed connections
          - Many packets to single destination (in flow context)
          - High ratio of SYN to total packets
        """
        syn_count = flow.get("syn_count", 0)
        total_packets = flow.get("total_fwd_packets", 0) + flow.get("total_bwd_packets", 0)
        fin_count = flow.get("fin_count", 0)
        rst_count = flow.get("rst_count", 0)
        
        if total_packets == 0:
            return 0.0
        
        # Port scans typically have many SYNs, few FINs/RSTs
        syn_ratio = syn_count / total_packets if total_packets > 0 else 0
        
        # High SYN ratio (>0.8) with low completion suggests scan
        if syn_count > 20 and syn_ratio > 0.7:
            completed = fin_count + rst_count
            if completed < syn_count * 0.3:  # <30% completed
                return 0.85
        
        # Moderate signal
        if syn_count > 10 and syn_ratio > 0.5:
            return 0.5
        
        return 0.0
    
    def _check_dos_flow(self, flow: Dict) -> float:
        """
        Check if flow features indicate a DoS attack.
        
        Key indicators:
          - Very high packets per second
          - High packet count in short duration
          - Asymmetric traffic (many forward, few backward)
        """
        total_packets = flow.get("total_fwd_packets", 0) + flow.get("total_bwd_packets", 0)
        duration_us = flow.get("flow_duration", 0)
        duration_sec = duration_us / 1_000_000 if duration_us > 0 else 0
        fwd_packets = flow.get("total_fwd_packets", 0)
        bwd_packets = flow.get("total_bwd_packets", 0)
        
        if duration_sec == 0 or total_packets == 0:
            return 0.0
        
        pps = total_packets / duration_sec
        
        # High packet rate
        if pps > self.dos_rate:
            # Check asymmetry (flood attacks are one-sided)
            if bwd_packets > 0:
                asymmetry = fwd_packets / bwd_packets
                if asymmetry > 5:  # 5x more forward than backward
                    return 0.9
            return 0.8
        
        # Moderate rate with high volume
        if total_packets > 100 and pps > 20:
            return 0.5
        
        return 0.0
    
    # ──────────────────────────────────────────────────────────
    # Packet-Level Rules (use raw packets for payload inspection)
    # ──────────────────────────────────────────────────────────
    
    def evaluate_packet(self, packet: Packet, timestamp: Optional[float] = None) -> Dict:
        """
        Evaluate a single raw packet against stateful and signature rules.
        
        Args:
            packet: Scapy Packet object
            timestamp: Optional timestamp (uses packet.time if not provided)
            
        Returns:
            Dict with detection results
        """
        if timestamp is None:
            timestamp = packet.time if hasattr(packet, 'time') else time.time()
        
        result = {
            "portscan_alert": False,
            "dos_alert": False,
            "webattack_alert": False,
            "webattack_type": None,
            "webattack_detail": None,
        }
        
        # Only process IP packets
        if IP not in packet:
            return result
        
        src_ip = packet[IP].src
        dst_port = None
        payload = ""
        is_syn_scan = False
        is_encrypted_tls = False
        
        # Extract port, flags, and payload
        if TCP in packet:
            dst_port = packet[TCP].dport
            flags = str(packet[TCP].flags)
            # Only count SYN packets (without ACK) for port scanning
            if "S" in flags and "A" not in flags:
                is_syn_scan = True
            
            if Raw in packet:
                raw_bytes = packet[Raw].load
                # Check for TLS Handshake / Application Data headers
                if dst_port in [443, 8443, 993, 995] or raw_bytes.startswith((b'\x16\x03', b'\x17\x03', b'\x14\x03', b'\x15\x03')):
                    is_encrypted_tls = True
                else:
                    try:
                        # Only inspect if it looks like ASCII/UTF-8 text or HTTP request
                        if any(raw_bytes.startswith(m) for m in [b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"HTTP/"]):
                            payload = raw_bytes.decode('utf-8', errors='ignore')
                        elif not is_encrypted_tls and len(raw_bytes) < 4096:
                            # Verify if it's mostly printable ASCII
                            printable_count = sum(1 for b in raw_bytes[:256] if 32 <= b <= 126 or b in (9, 10, 13))
                            if printable_count / max(1, min(len(raw_bytes), 256)) > 0.85:
                                payload = raw_bytes.decode('utf-8', errors='ignore')
                    except Exception:
                        payload = ""
        elif UDP in packet:
            dst_port = packet[UDP].dport
            if Raw in packet:
                raw_bytes = packet[Raw].load
                if dst_port not in [53, 443]:
                    try:
                        printable_count = sum(1 for b in raw_bytes[:256] if 32 <= b <= 126 or b in (9, 10, 13))
                        if printable_count / max(1, min(len(raw_bytes), 256)) > 0.85:
                            payload = raw_bytes.decode('utf-8', errors='ignore')
                    except Exception:
                        payload = ""
        
        # Stateful tracking:
        # Rate tracking for DoS
        self.tracker.add_packet(src_ip, timestamp)
        
        # PortScan tracking: ONLY track SYN probe attempts, not established sessions
        if dst_port and is_syn_scan:
            self.tracker.add_connection(src_ip, dst_port, timestamp)
            unique_ports = self.tracker.get_unique_ports(src_ip, timestamp)
            if unique_ports >= self.portscan_ports:
                result["portscan_alert"] = True
        
        # Check DoS: Detect actual floods (UDP flood, SYN flood, ICMP flood, high-rate request flood)
        # Standard established TCP downloads/responses (ACK / PSH-ACK from web servers) are normal data transfers
        is_normal_web_dl = (TCP in packet and (packet[TCP].sport in [80, 443, 8080, 8443] or ("A" in str(packet[TCP].flags) and "S" not in str(packet[TCP].flags))))
        if not is_normal_web_dl:
            packet_count = self.tracker.get_packet_count(src_ip, timestamp)
            packet_rate = self.tracker.get_packet_rate(src_ip, timestamp)
            if packet_count >= self.dos_packets or packet_rate >= self.dos_rate:
                result["dos_alert"] = True
        
        # Check WebAttack (payload inspection on plaintext only)
        if payload and not is_encrypted_tls:
            web_result = self._check_webattack_payload(payload)
            if web_result:
                result["webattack_alert"] = True
                result["webattack_type"] = web_result[0]
                result["webattack_detail"] = web_result[1]
        
        return result
    
    def _check_webattack_payload(self, payload: str) -> Optional[Tuple[str, str]]:
        """
        Inspect HTTP payload for web attack signatures.
        
        Returns:
            (attack_type, matched_pattern) if detected, None otherwise
        """
        # Check SQL Injection
        for pattern in self.sql_patterns:
            match = pattern.search(payload)
            if match:
                return ("SQL Injection", match.group(0)[:100])
        
        # Check XSS
        for pattern in self.xss_patterns:
            match = pattern.search(payload)
            if match:
                return ("XSS", match.group(0)[:100])
        
        # Check Path Traversal
        for pattern in self.path_patterns:
            match = pattern.search(payload)
            if match:
                return ("Path Traversal", match.group(0)[:100])
        
        return None
    
    # ──────────────────────────────────────────────────────────
    # Utility
    # ──────────────────────────────────────────────────────────
    
    def get_rule_score(self, flow_features: Dict = None, packet: Packet = None) -> float:
        """
        Get the overall rule engine confidence score (0.0 to 1.0).
        
        Used by the weighted fusion system.
        Combines flow-level and packet-level detections.
        
        Args:
            flow_features: Optional flow features dict
            packet: Optional raw packet
            
        Returns:
            Confidence score 0.0 (no detection) to 1.0 (high confidence)
        """
        scores = []
        
        if flow_features:
            flow_scores = self.evaluate_flow(flow_features)
            scores.append(flow_scores.get("portscan_score", 0.0))
            scores.append(flow_scores.get("dos_score", 0.0))
        
        if packet:
            packet_result = self.evaluate_packet(packet)
            if packet_result["portscan_alert"]:
                scores.append(0.9)
            if packet_result["dos_alert"]:
                scores.append(0.9)
            if packet_result["webattack_alert"]:
                scores.append(0.95)
        
        return max(scores) if scores else 0.0
    
    def reset(self) -> None:
        """Reset all stateful tracking data."""
        self.tracker = ConnectionTracker(max(self.portscan_window, self.dos_window))
    
    def get_stats(self) -> Dict:
        """Return current tracking statistics."""
        return {
            "tracked_ips": len(self.tracker.connections),
            "active_connections": sum(len(v) for v in self.tracker.connections.values()),
        }

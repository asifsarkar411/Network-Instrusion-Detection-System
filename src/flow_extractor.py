"""
Flow extraction module.

Groups raw packets into bidirectional flows and computes statistical features
matching CICFlowMeter's definitions for NIDS analysis.

Architecture:
  - Ingest packets from the ring buffer
  - Group by 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol)
  - Compute 25 flow features when flow ends or times out
  - Push completed flows to an output queue for the analysis engine
"""

import time
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from queue import Queue
import statistics
import math

from scapy.packet import Packet
from scapy.layers.inet import IP, TCP, UDP


# ──────────────────────────────────────────────────────────────
# Data Classes
# ──────────────────────────────────────────────────────────────

@dataclass
class FlowStats:
    """
    Accumulates packet-level statistics for a single bidirectional flow.
    
    A flow is identified by the 5-tuple:
    (src_ip, dst_ip, src_port, dst_port, protocol)
    
    Direction is determined by the first packet seen:
    - Forward = same direction as first packet
    - Backward = opposite direction
    """
    
    # Flow identification
    flow_key: Tuple[str, str, int, int, int]
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int  # 6=TCP, 17=UDP
    
    # Timing
    first_seen: float = 0.0
    last_seen: float = 0.0
    last_packet_time: float = 0.0
    
    # Direction tracking (set on first packet)
    initiator_ip: Optional[str] = None
    
    # Forward direction stats
    fwd_packet_count: int = 0
    fwd_byte_count: int = 0
    fwd_packet_lengths: List[int] = field(default_factory=list)
    fwd_timestamps: List[float] = field(default_factory=list)
    
    # Backward direction stats
    bwd_packet_count: int = 0
    bwd_byte_count: int = 0
    bwd_packet_lengths: List[int] = field(default_factory=list)
    bwd_timestamps: List[float] = field(default_factory=list)
    
    # Flag counts (TCP only)
    syn_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    ack_count: int = 0
    urg_count: int = 0
    
    # Directional flag counts
    fwd_psh_count: int = 0
    bwd_psh_count: int = 0
    
    def update(self, packet: Packet) -> None:
        """
        Update flow statistics with a new packet.
        
        Args:
            packet: A scapy Packet object containing IP and TCP/UDP layers.
        """
        now = packet.time
        pkt_len = len(packet)
        
        # Initialize timing
        if self.first_seen == 0.0:
            self.first_seen = now
            # Determine initiator direction from this first packet
            if IP in packet:
                self.initiator_ip = packet[IP].src
        
        self.last_seen = now
        self.last_packet_time = now
        
        # Determine direction
        is_forward = self._is_forward(packet)
        
        # Update directional stats
        if is_forward:
            self.fwd_packet_count += 1
            self.fwd_byte_count += pkt_len
            self.fwd_packet_lengths.append(pkt_len)
            self.fwd_timestamps.append(now)
        else:
            self.bwd_packet_count += 1
            self.bwd_byte_count += pkt_len
            self.bwd_packet_lengths.append(pkt_len)
            self.bwd_timestamps.append(now)
        
        # TCP flags
        if TCP in packet:
            flags = packet[TCP].flags
            if flags & 0x02:  # SYN
                self.syn_count += 1
            if flags & 0x01:  # FIN
                self.fin_count += 1
            if flags & 0x04:  # RST
                self.rst_count += 1
            if flags & 0x08:  # PSH
                self.psh_count += 1
                if is_forward:
                    self.fwd_psh_count += 1
                else:
                    self.bwd_psh_count += 1
            if flags & 0x10:  # ACK
                self.ack_count += 1
            if flags & 0x20:  # URG
                self.urg_count += 1
    
    def _is_forward(self, packet: Packet) -> bool:
        """
        Determine if this packet is in the forward direction.
        
        Forward = same source as the first packet's source.
        """
        if IP not in packet or self.initiator_ip is None:
            return True
        return packet[IP].src == self.initiator_ip
    
    def is_expired(self, current_time: float, timeout: float) -> bool:
        """Check if the flow has timed out."""
        return (current_time - self.last_packet_time) > timeout
    
    def is_finished(self, packet: Packet) -> bool:
        """
        Check if this packet terminates the flow.
        
        For TCP: FIN or RST flag indicates flow termination.
        For UDP: UDP has no termination signal — rely on timeout only.
        """
        if TCP in packet:
            flags = packet[TCP].flags
            return bool(flags & 0x01) or bool(flags & 0x04)  # FIN or RST
        return False
    
    def compute_features(self) -> Dict[str, float]:
        """
        Compute the 25 flow features matching CICFlowMeter definitions.
        
        Returns:
            Dictionary of feature_name -> float value.
            Returns -1 for features that cannot be computed
            (e.g., division by zero).
        """
        duration = (self.last_seen - self.first_seen) * 1_000_000  # microseconds
        
        # Helper: safe division
        def safe_div(a, b):
            return a / b if b != 0 else -1.0
        
        # Helper: safe std dev
        def safe_stdev(values):
            return statistics.stdev(values) if len(values) >= 2 else 0.0
        
        # Inter-arrival times
        all_timestamps = sorted(self.fwd_timestamps + self.bwd_timestamps)
        iat_list = [all_timestamps[i] - all_timestamps[i-1] 
                    for i in range(1, len(all_timestamps))]
        
        fwd_iat = [self.fwd_timestamps[i] - self.fwd_timestamps[i-1]
                   for i in range(1, len(self.fwd_timestamps))]
        
        bwd_iat = [self.bwd_timestamps[i] - self.bwd_timestamps[i-1]
                   for i in range(1, len(self.bwd_timestamps))]
        
        features = {
            # Basic metrics
            "flow_duration": duration,
            "total_fwd_packets": self.fwd_packet_count,
            "total_bwd_packets": self.bwd_packet_count,
            "total_fwd_bytes": self.fwd_byte_count,
            "total_bwd_bytes": self.bwd_byte_count,
            
            # Packet length statistics
            "fwd_packet_len_mean": statistics.mean(self.fwd_packet_lengths) if self.fwd_packet_lengths else 0.0,
            "bwd_packet_len_mean": statistics.mean(self.bwd_packet_lengths) if self.bwd_packet_lengths else 0.0,
            "fwd_packet_len_std": safe_stdev(self.fwd_packet_lengths),
            "bwd_packet_len_std": safe_stdev(self.bwd_packet_lengths),
            
            # Rate features (per second)
            "flow_bytes_per_sec": safe_div(
                self.fwd_byte_count + self.bwd_byte_count,
                duration / 1_000_000
            ),
            "flow_packets_per_sec": safe_div(
                self.fwd_packet_count + self.bwd_packet_count,
                duration / 1_000_000
            ),
            "fwd_packets_per_sec": safe_div(
                self.fwd_packet_count,
                duration / 1_000_000
            ) if duration > 0 else 0.0,
            "bwd_packets_per_sec": safe_div(
                self.bwd_packet_count,
                duration / 1_000_000
            ) if duration > 0 else 0.0,
            
            # Inter-arrival time statistics
            "flow_iat_mean": statistics.mean(iat_list) if iat_list else 0.0,
            "flow_iat_std": safe_stdev(iat_list),
            "fwd_iat_mean": statistics.mean(fwd_iat) if fwd_iat else 0.0,
            "bwd_iat_mean": statistics.mean(bwd_iat) if bwd_iat else 0.0,
            
            # TCP flag counts
            "syn_count": self.syn_count,
            "fin_count": self.fin_count,
            "rst_count": self.rst_count,
            "psh_count": self.psh_count,
            "ack_count": self.ack_count,
            "urg_count": self.urg_count,
            "fwd_psh_flags": self.fwd_psh_count,
            "bwd_psh_flags": self.bwd_psh_count,
        }
        
        return features


# ──────────────────────────────────────────────────────────────
# Flow Extractor
# ──────────────────────────────────────────────────────────────

class FlowExtractor:
    """
    Extracts bidirectional flows from raw packets.
    
    Runs a background thread that:
      1. Reads packets from the ring buffer
      2. Groups them into flows
      3. Computes features when flows end or time out
      4. Pushes completed flow features to an output queue
    """
    
    def __init__(
        self,
        ring_buffer,  # PacketRingBuffer from capture module
        flow_timeout: float = 60.0,
        gc_interval: float = 5.0,
        max_active_flows: int = 500,
    ):
        self.ring_buffer = ring_buffer
        self.flow_timeout = flow_timeout
        self.gc_interval = gc_interval
        self.max_active_flows = max_active_flows
        
        # Active flows: flow_key -> FlowStats
        self.active_flows: Dict[Tuple, FlowStats] = {}
        
        # Completed flow features ready for analysis
        self.output_queue: Queue = Queue()
        
        # Threading
        self._stop_event = threading.Event()
        self._extractor_thread: Optional[threading.Thread] = None
        self._gc_thread: Optional[threading.Thread] = None
        
        # Statistics
        self.flows_completed: int = 0
        self.packets_processed: int = 0
        self.last_packet_index: int = 0
    
    @staticmethod
    def get_flow_key(packet: Packet) -> Optional[Tuple]:
        """
        Extract a normalized 5-tuple flow key from a packet.
        
        Normalization: sorts IPs and ports so bidirectional
        packets map to the same flow key.
        
        Returns None if packet doesn't have IP + TCP/UDP layers.
        """
        if IP not in packet:
            return None
        
        ip_layer = packet[IP]
        proto = ip_layer.proto
        
        # Determine ports based on protocol
        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        else:
            return None  # Skip non-TCP/UDP
        
        # Normalize: always put smaller (IP, port) first
        if (ip_layer.src, sport) < (ip_layer.dst, dport):
            return (ip_layer.src, ip_layer.dst, sport, dport, proto)
        else:
            return (ip_layer.dst, ip_layer.src, dport, sport, proto)
    
    def _process_packet(self, packet: Packet) -> Optional[Dict]:
        """
        Process a single packet: add to existing flow or create new flow.
        
        Returns:
            Flow features dict if this packet caused a flow to finish,
            None otherwise.
        """
        flow_key = self.get_flow_key(packet)
        if flow_key is None:
            return None
        
        # Check if we need to create a new flow
        if flow_key not in self.active_flows:
            # Enforce max active flows limit
            if len(self.active_flows) >= self.max_active_flows:
                # Force-expire the oldest flow
                oldest_key = min(
                    self.active_flows.keys(),
                    key=lambda k: self.active_flows[k].last_packet_time
                )
                old_flow = self.active_flows.pop(oldest_key)
                self.flows_completed += 1
                return old_flow.compute_features()
            
            # Create new flow
            ip_layer = packet[IP]
            self.active_flows[flow_key] = FlowStats(
                flow_key=flow_key,
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                src_port=flow_key[2],
                dst_port=flow_key[3],
                protocol=flow_key[4],
            )
        
        flow = self.active_flows[flow_key]
        flow.update(packet)
        
        # Check if flow is finished (TCP FIN/RST)
        if flow.is_finished(packet):
            del self.active_flows[flow_key]
            self.flows_completed += 1
            return flow.compute_features()
        
        return None
    
    def _garbage_collect(self) -> None:
        """
        Periodically check for expired flows and flush them.
        Runs in a separate thread.
        """
        while not self._stop_event.is_set():
            self._stop_event.wait(self.gc_interval)
            
            current_time = time.time()
            expired_keys = []
            
            for flow_key, flow in self.active_flows.items():
                if flow.is_expired(current_time, self.flow_timeout):
                    expired_keys.append(flow_key)
            
            for flow_key in expired_keys:
                flow = self.active_flows.pop(flow_key)
                features = flow.compute_features()
                self.output_queue.put(features)
                self.flows_completed += 1
            
            if expired_keys:
                pass # print(f"[FlowExtractor] GC: flushed {len(expired_keys)} expired flows")
    
    def _run_extraction(self) -> None:
        """
        Main extraction loop. Reads from ring buffer and processes packets.
        """
        print(f"[FlowExtractor] Started (timeout={self.flow_timeout}s, max_flows={self.max_active_flows})")
        
        while not self._stop_event.is_set():
            # Get new packets since last check
            all_packets = self.ring_buffer.get_all()
            new_packets = all_packets[self.last_packet_index:]
            self.last_packet_index = len(all_packets)
            
            for packet in new_packets:
                self.packets_processed += 1
                result = self._process_packet(packet)
                
                if result is not None:
                    self.output_queue.put(result)
            
            # Small sleep to prevent busy-waiting
            self._stop_event.wait(0.1)
        
        # Final flush on stop
        print("[FlowExtractor] Stopping — flushing remaining flows...")
        for flow_key, flow in list(self.active_flows.items()):
            features = flow.compute_features()
            self.output_queue.put(features)
            self.flows_completed += 1
            del self.active_flows[flow_key]
        print(f"[FlowExtractor] Flushed {self.flows_completed} total flows")
    
    def start(self) -> None:
        """Start flow extraction in background threads."""
        if self._extractor_thread and self._extractor_thread.is_alive():
            print("[FlowExtractor] Already running.")
            return
        
        self._stop_event.clear()
        
        # Start garbage collector thread
        self._gc_thread = threading.Thread(
            target=self._garbage_collect,
            daemon=True
        )
        self._gc_thread.start()
        
        # Start extraction thread
        self._extractor_thread = threading.Thread(
            target=self._run_extraction,
            daemon=True
        )
        self._extractor_thread.start()
        
        print("[FlowExtractor] Threads started")
    
    def stop(self) -> None:
        """Gracefully stop flow extraction."""
        self._stop_event.set()
        
        if self._extractor_thread:
            self._extractor_thread.join(timeout=5)
        if self._gc_thread:
            self._gc_thread.join(timeout=5)
        
        print("[FlowExtractor] Stopped")
    
    def get_completed_flows(self) -> List[Dict]:
        """
        Drain the output queue and return all completed flow features.
        Non-blocking — returns empty list if queue is empty.
        """
        results = []
        while not self.output_queue.empty():
            try:
                results.append(self.output_queue.get_nowait())
            except:
                break
        return results
    
    def get_stats(self) -> Dict:
        """Return current extraction statistics."""
        return {
            "active_flows": len(self.active_flows),
            "flows_completed": self.flows_completed,
            "packets_processed": self.packets_processed,
            "output_queue_size": self.output_queue.qsize(),
        }

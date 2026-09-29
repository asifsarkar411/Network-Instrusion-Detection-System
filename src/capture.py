"""
Packet capture module using scapy with an in-memory ring buffer.
Captures live network traffic on a background thread.
"""

import time
import threading
from collections import deque
from typing import Optional, Callable, List
import yaml
from scapy.all import sniff, conf
from scapy.packet import Packet


class PacketRingBuffer:
    """
    Thread-safe ring buffer for captured packets.
    
    Uses collections.deque with a maximum length. When the buffer is full,
    the oldest packet is automatically removed to make room for the new one.
    This keeps memory usage constant regardless of capture duration.
    """

    def __init__(self, maxlen: int = 10000):
        self._buffer = deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def append(self, packet: Packet) -> None:
        """Add a packet to the buffer. Thread-safe."""
        with self._lock:
            self._buffer.append(packet)

    def get_all(self) -> List[Packet]:
        """Return a snapshot of all packets currently in the buffer."""
        with self._lock:
            return list(self._buffer)

    def clear(self) -> None:
        """Empty the buffer."""
        with self._lock:
            self._buffer.clear()

    def __len__(self) -> int:
        """Return current number of packets in the buffer."""
        with self._lock:
            return len(self._buffer)


class LiveCapture:
    """
    Manages live packet capture on a dedicated background thread.
    
    Reads configuration from config.yaml. Uses scapy's sniff() function
    with a callback that feeds packets into the ring buffer.
    """

    def __init__(self, config_path: str = "config.yaml"):
        # Load configuration
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)["capture"]

        # Use the interface from config, or auto-detect if null/empty
        self.interface = self.config.get("interface") or conf.iface
        
        # Convert minutes to seconds for scapy's timeout parameter
        self.duration = self.config.get("duration_minutes", 25) * 60
        
        # Create the ring buffer with configured size
        self.ring_buffer = PacketRingBuffer(
            maxlen=self.config.get("ring_buffer_size", 10000)
        )
        
        # Threading controls
        self._stop_event = threading.Event()
        self._capture_thread: Optional[threading.Thread] = None
        
        # Statistics
        self.packets_captured = 0
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None

    def _packet_callback(self, packet: Packet) -> None:
        """
        Called by scapy for every captured packet.
        
        This runs in scapy's capture thread, so it must be fast.
        We simply append to the ring buffer and increment the counter.
        """
        self.ring_buffer.append(packet)
        self.packets_captured += 1

    def _run_capture(self) -> None:
        """
        Target function for the capture thread.
        
        Calls scapy's sniff() which blocks until timeout or stop signal.
        """
        try:
            self.start_time = time.time()
            print(f"[Capture] Starting on interface: {self.interface}")
            print(f"[Capture] Duration: {self.config.get('duration_minutes', 25)} minutes")
            print(f"[Capture] BPF Filter: {self.config.get('bpf_filter', 'none')}")
            print(f"[Capture] Ring buffer size: {self.config.get('ring_buffer_size', 10000)}")
            print("-" * 50)
            
            sniff(
                iface=self.interface,
                prn=self._packet_callback,
                store=False,
                timeout=self.duration,
                stop_filter=lambda _: self._stop_event.is_set(),
                filter=self.config.get("bpf_filter") or None,
            )
        except PermissionError:
            print("\n[ERROR] Administrator privileges required for packet capture.")
            print("[ERROR] Please run this script from an Administrator PowerShell.")
            self._run_simulation()
        except OSError as e:
            print(f"\n[ERROR] Could not open interface '{self.interface}': {e}")
            print("[ERROR] Check that the interface name in config.yaml is correct.")
            self._run_simulation()
        except RuntimeError as e:
            print(f"\n[ERROR] Runtime Error (Likely Npcap missing): {e}")
            self._run_simulation()
        except Exception as e:
            print(f"\n[ERROR] Unexpected capture error: {e}")
            self._run_simulation()
        finally:
            self.end_time = time.time()

    def _run_simulation(self) -> None:
        """Fallback method to generate synthetic packets if live capture fails."""
        import random
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.l2 import Ether
        from scapy.packet import Raw
        
        print("\n[WARNING] Entering SIMULATION MODE. Generating synthetic packets...")
        
        start_sim = time.time()
        
        while not self._stop_event.is_set():
            if time.time() - start_sim > self.duration:
                break
                
            src_ip = f"192.168.1.{random.randint(10, 200)}"
            dst_ip = f"10.0.0.{random.randint(1, 50)}"
            
            proto = random.choice([TCP, TCP, UDP, ICMP])
            
            # 10% chance to generate an attack packet to light up the Packet Inspector
            if random.random() < 0.1:
                pkt = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=random.randint(1024, 65535), dport=80)/Raw(b"GET /login.php?user=' OR 1=1 HTTP/1.1")
            else:
                if proto == TCP:
                    pkt = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=random.randint(1024, 65535), dport=random.choice([80, 443, 22]))/Raw(b"simulated tcp")
                elif proto == UDP:
                    pkt = Ether()/IP(src=src_ip, dst=dst_ip)/UDP(sport=random.randint(1024, 65535), dport=53)/Raw(b"simulated udp")
                else:
                    pkt = Ether()/IP(src=src_ip, dst=dst_ip)/ICMP()/Raw(b"simulated icmp")
                
            self._packet_callback(pkt)
            time.sleep(random.uniform(0.01, 0.1))

    def start(self) -> None:
        """
        Start capturing packets in a background thread.
        
        Safe to call multiple times — will not start a duplicate capture.
        """
        if self._capture_thread and self._capture_thread.is_alive():
            print("[Capture] Already running.")
            return

        self._stop_event.clear()
        self.packets_captured = 0
        self._capture_thread = threading.Thread(
            target=self._run_capture, 
            daemon=True
        )
        self._capture_thread.start()
        time.sleep(0.5)  # Give the thread a moment to initialize

    def stop(self) -> None:
        """
        Gracefully stop the capture.
        
        Signals the capture thread to exit and waits up to 5 seconds
        for it to finish.
        """
        if not self._capture_thread or not self._capture_thread.is_alive():
            print("[Capture] Not running.")
            return

        print("[Capture] Stopping...")
        self._stop_event.set()
        self._capture_thread.join(timeout=5)
        
        if self._capture_thread.is_alive():
            print("[Capture] Warning: Capture thread did not stop within 5 seconds.")
        else:
            print("[Capture] Stopped successfully.")

    def get_packets(self) -> List[Packet]:
        """Return a snapshot of all currently captured packets."""
        return self.ring_buffer.get_all()

    def get_stats(self) -> dict:
        """Return capture statistics."""
        duration = 0
        if self.start_time:
            end = self.end_time or time.time()
            duration = end - self.start_time
        
        return {
            "interface": self.interface,
            "packets_captured": self.packets_captured,
            "packets_in_buffer": len(self.ring_buffer),
            "duration_seconds": round(duration, 1),
            "is_running": self._capture_thread.is_alive() if self._capture_thread else False,
        }

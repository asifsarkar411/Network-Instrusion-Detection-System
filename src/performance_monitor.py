"""
Performance Monitor
===================
Tracks system resources and detection pipeline performance.
Provides real-time metrics for the dashboard.
"""

import time
import threading
import psutil
import os
from collections import deque
from typing import Dict, Optional
import numpy as np


class PerformanceMonitor:
    """
    Monitors system and pipeline performance in real-time.
    
    Tracks:
      - CPU usage (%)
      - Memory usage (MB)
      - Inference latency (ms)
      - Packets per second
      - Flows per second
      - Alerts per minute
      - Uptime
    """
    
    def __init__(self, history_size: int = 120):
        """
        Args:
            history_size: Number of data points to keep for trends
        """
        self.process = psutil.Process(os.getpid())
        self.history_size = history_size
        
        # Performance history (for trend charts)
        self.cpu_history = deque(maxlen=history_size)
        self.memory_history = deque(maxlen=history_size)
        self.pps_history = deque(maxlen=history_size)       # Packets per second
        self.fps_history = deque(maxlen=history_size)       # Flows per second
        self.latency_history = deque(maxlen=history_size)   # Inference latency
        
        # Counters
        self.packets_total = 0
        self.flows_total = 0
        self.alerts_total = 0
        self.predictions_total = 0
        self.total_latency = 0.0
        
        # Timing
        self.start_time = time.time()
        self.last_sample_time = time.time()
        self.last_packet_count = 0
        self.last_flow_count = 0
        
        # Threading
        self._stop_event = threading.Event()
        self._monitor_thread: Optional[threading.Thread] = None
        
        # Latest metrics
        self.cpu_percent = 0.0
        self.memory_mb = 0.0
        self.pps = 0.0
        self.fps = 0.0
        self.avg_latency = 0.0
        self.uptime = 0
    
    def _sample(self) -> Dict:
        """Take a single performance sample."""
        # CPU and Memory
        self.cpu_percent = self.process.cpu_percent(interval=0.1) / psutil.cpu_count()
        self.memory_mb = self.process.memory_info().rss / (1024 * 1024)
        
        # Packet rate
        now = time.time()
        elapsed = now - self.last_sample_time
        if elapsed > 0:
            self.pps = (self.packets_total - self.last_packet_count) / elapsed
            self.fps = (self.flows_total - self.last_flow_count) / elapsed
        
        self.last_packet_count = self.packets_total
        self.last_flow_count = self.flows_total
        self.last_sample_time = now
        self.uptime = now - self.start_time
        
        # Average latency
        if self.predictions_total > 0:
            self.avg_latency = (self.total_latency / self.predictions_total) * 1000  # ms
        
        # Store history
        self.cpu_history.append(self.cpu_percent)
        self.memory_history.append(self.memory_mb)
        self.pps_history.append(self.pps)
        self.fps_history.append(self.fps)
        self.latency_history.append(self.avg_latency)
        
        return self.get_metrics()
    
    def _run(self):
        """Background monitoring loop."""
        while not self._stop_event.is_set():
            self._sample()
            self._stop_event.wait(1.0)  # Sample every second
    
    def start(self):
        """Start background monitoring."""
        if self._monitor_thread and self._monitor_thread.is_alive():
            return
        
        self.start_time = time.time()
        self._stop_event.clear()
        self._monitor_thread = threading.Thread(target=self._run, daemon=True)
        self._monitor_thread.start()
        print("[PerformanceMonitor] Started")
    
    def stop(self):
        """Stop monitoring."""
        self._stop_event.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=3)
        print("[PerformanceMonitor] Stopped")
    
    def record_packet(self, count: int = 1):
        """Record captured packets."""
        self.packets_total += count
    
    def record_flow(self, count: int = 1):
        """Record processed flows."""
        self.flows_total += count
    
    def record_prediction(self, latency_seconds: float):
        """Record a single prediction with its latency."""
        self.predictions_total += 1
        self.total_latency += latency_seconds
    
    def record_alert(self, count: int = 1):
        """Record generated alerts."""
        self.alerts_total += count
    
    def get_metrics(self) -> Dict:
        """Get current performance metrics."""
        return {
            "cpu_percent": round(self.cpu_percent, 1),
            "memory_mb": round(self.memory_mb, 1),
            "packets_per_sec": round(self.pps, 1),
            "flows_per_sec": round(self.fps, 1),
            "avg_latency_ms": round(self.avg_latency, 2),
            "uptime_seconds": int(self.uptime),
            "uptime_str": self._format_uptime(),
            "total_packets": self.packets_total,
            "total_flows": self.flows_total,
            "total_alerts": self.alerts_total,
            "total_predictions": self.predictions_total,
            "cpu_history": list(self.cpu_history),
            "memory_history": list(self.memory_history),
            "pps_history": list(self.pps_history),
            "latency_history": list(self.latency_history),
        }
    
    def _format_uptime(self) -> str:
        """Format uptime seconds to human readable."""
        seconds = int(self.uptime)
        hours, remainder = divmod(seconds, 3600)
        minutes, secs = divmod(remainder, 60)
        if hours > 0:
            return f"{hours}h {minutes}m {secs}s"
        elif minutes > 0:
            return f"{minutes}m {secs}s"
        return f"{secs}s"
    
    def get_health_status(self) -> Dict:
        """Get system health assessment."""
        metrics = self.get_metrics()
        
        # Health checks
        cpu_ok = metrics["cpu_percent"] < 80
        mem_ok = metrics["memory_mb"] < 1024  # Under 1GB
        latency_ok = metrics["avg_latency_ms"] < 100  # Under 100ms
        pps_ok = metrics["packets_per_sec"] > 0 if self.uptime > 10 else True
        
        issues = []
        if not cpu_ok:
            issues.append(f"High CPU: {metrics['cpu_percent']}%")
        if not mem_ok:
            issues.append(f"High Memory: {metrics['memory_mb']:.0f}MB")
        if not latency_ok:
            issues.append(f"High Latency: {metrics['avg_latency_ms']}ms")
        
        all_ok = cpu_ok and mem_ok and latency_ok and pps_ok
        
        return {
            "healthy": all_ok,
            "status": "🟢 HEALTHY" if all_ok else "🟡 DEGRADED" if len(issues) < 2 else "🔴 CRITICAL",
            "issues": issues,
            "checks": {
                "cpu": cpu_ok,
                "memory": mem_ok,
                "latency": latency_ok,
                "throughput": pps_ok,
            }
        }

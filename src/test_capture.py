"""
Verification script for the capture module.

Tests:
  1. Capture module starts without errors
  2. Packets are captured during normal browsing
  3. Ring buffer stores packets correctly
  4. Basic packet fields are accessible
  5. Stop works gracefully

Run this from Administrator PowerShell:
    python src\test_capture.py
"""

import time
import sys
import os

# Add project root to path so we can import capture module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.capture import LiveCapture


def test_capture_short():
    """
    Run a 30-second capture test.
    
    During the test, browse the web normally to generate traffic.
    The test checks mid-capture and post-capture packet counts.
    """
    print("=" * 60)
    print("  SOC-NIDS Phase 0: Capture Module Verification")
    print("=" * 60)
    print()
    
    # Step 1: Initialize
    print("[TEST] Step 1: Initializing capture module...")
    capture = LiveCapture()
    capture.duration = 35  # 35 seconds total (30s wait + buffer)
    print(f"[TEST] Interface: {capture.interface}")
    print(f"[TEST] Duration: 30 seconds (test mode)")
    print()
    
    # Step 2: Start capture
    print("[TEST] Step 2: Starting capture...")
    capture.start()
    
    if not capture._capture_thread or not capture._capture_thread.is_alive():
        print("[FAIL] Capture thread failed to start.")
        print("[HINT] Check that:")
        print("       1. You are running from Administrator PowerShell")
        print("       2. The interface name in config.yaml is correct")
        print("       3. Npcap is installed in WinPcap API-compatible mode")
        return False
    
    print("[PASS] Capture thread started successfully.")
    print()
    
    # Step 3: Wait and check mid-capture
    print("[TEST] Step 3: Waiting 15 seconds...")
    print("        → Please browse the web to generate traffic now!")
    print()
    
    for i in range(15, 0, -1):
        print(f"\r        Time remaining: {i:2d} seconds...", end="", flush=True)
        time.sleep(1)
    print("\n")
    
    # Mid-capture check
    mid_packets = capture.get_packets()
    mid_stats = capture.get_stats()
    print(f"[CHECK] Mid-capture packet count: {len(mid_packets)}")
    print(f"[CHECK] Packets captured total: {mid_stats['packets_captured']}")
    
    if len(mid_packets) > 0:
        print("[PASS] Packets are flowing into the ring buffer.")
        # Show first packet
        first = mid_packets[0]
        print(f"[SAMPLE] First packet: {first.summary()}")
    else:
        print("[WARN] No packets captured yet. This could mean:")
        print("       1. No network traffic on this interface")
        print("       2. BPF filter is too restrictive")
        print("       3. Interface is wrong")
    print()
    
    # Step 4: Wait more
    print("[TEST] Step 4: Waiting another 15 seconds...")
    for i in range(15, 0, -1):
        print(f"\r        Time remaining: {i:2d} seconds...", end="", flush=True)
        time.sleep(1)
    print("\n")
    
    # Step 5: Stop capture
    print("[TEST] Step 5: Stopping capture...")
    capture.stop()
    print()
    
    # Step 6: Final verification
    print("[TEST] Step 6: Final verification...")
    final_packets = capture.get_packets()
    final_stats = capture.get_stats()
    
    print(f"        Total packets captured: {final_stats['packets_captured']}")
    print(f"        Packets in buffer:      {final_stats['packets_in_buffer']}")
    print(f"        Capture duration:       {final_stats['duration_seconds']} seconds")
    print()
    
    # Show diverse packet samples
    if len(final_packets) > 0:
        print("[PACKET SAMPLES]")
        # Show up to 5 different packets
        for i, pkt in enumerate(final_packets[:5]):
            print(f"        [{i+1}] {pkt.summary()}")
        print()
    
    # Step 7: Evaluate results
    print("=" * 60)
    print("  RESULTS")
    print("=" * 60)
    
    all_passed = True
    
    # Check 1: Capture started
    print(f"[{'PASS' if final_stats['packets_captured'] > 0 else 'FAIL'}] "
          f"Packets captured: {final_stats['packets_captured']}")
    if final_stats['packets_captured'] == 0:
        all_passed = False
    
    # Check 2: Ring buffer works
    buffer_ok = len(final_packets) > 0
    print(f"[{'PASS' if buffer_ok else 'FAIL'}] "
          f"Ring buffer contains packets: {len(final_packets)}")
    if not buffer_ok:
        all_passed = False
    
    # Check 3: Packet parsing works
    parse_ok = len(final_packets) > 0 and hasattr(final_packets[0], 'summary')
    print(f"[{'PASS' if parse_ok else 'FAIL'}] "
          f"Packet parsing (scapy summary available)")
    if not parse_ok:
        all_passed = False
    
    # Check 4: Threshold met (>50 packets)
    threshold_ok = final_stats['packets_captured'] > 50
    print(f"[{'PASS' if threshold_ok else 'WARN'}] "
          f"More than 50 packets captured ({final_stats['packets_captured']})")
    # Not a hard fail — depends on network activity
    
    print()
    if all_passed:
        print("=" * 60)
        print("  PHASE 0 COMPLETE — Capture module is working!")
        print("=" * 60)
        return True
    else:
        print("=" * 60)
        print("  PHASE 0 INCOMPLETE — Some checks failed.")
        print("=" * 60)
        print()
        print("Troubleshooting:")
        print("  1. Make sure you're running as Administrator")
        print("  2. Check interface name: run IFACES.show() from scapy")
        print("  3. Verify Npcap is in 'WinPcap API-compatible Mode'")
        print("  4. Try disabling BPF filter temporarily in config.yaml")
        return False


if __name__ == "__main__":
    success = test_capture_short()
    sys.exit(0 if success else 1)

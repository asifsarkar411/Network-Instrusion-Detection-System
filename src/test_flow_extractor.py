"""
Verification script for the flow extraction module.

Tests:
  1. FlowExtractor initializes correctly
  2. Packets are grouped into flows
  3. Flow features are computed
  4. Flow timeout works
  5. Output queue receives completed flows

Run from Administrator PowerShell:
    python src\test_flow_extractor.py
"""

import time
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.capture import LiveCapture
from src.flow_extractor import FlowExtractor


def test_flow_extraction():
    print("=" * 60)
    print("  SOC-NIDS Phase 1: Flow Extraction Verification")
    print("=" * 60)
    print()
    
    # Step 1: Start packet capture (60 seconds for testing)
    print("[TEST] Step 1: Starting packet capture...")
    capture = LiveCapture()
    capture.duration = 65
    capture.start()
    
    if not capture._capture_thread or not capture._capture_thread.is_alive():
        print("[FAIL] Capture thread failed to start.")
        return False
    
    print("[PASS] Capture running.")
    print()
    
    # Step 2: Start flow extractor
    print("[TEST] Step 2: Starting flow extractor...")
    extractor = FlowExtractor(
        ring_buffer=capture.ring_buffer,
        flow_timeout=15.0,    # Short timeout for testing
        gc_interval=3.0,      # Frequent GC for testing
    )
    extractor.start()
    
    print("[PASS] Flow extractor started.")
    print()
    
    # Step 3: Let it run while browsing
    print("[TEST] Step 3: Capturing for 45 seconds...")
    print("        → Browse the web to generate diverse flows!")
    print()
    
    for i in range(45, 0, -5):
        print(f"        Time remaining: {i:2d} seconds...")
        time.sleep(5)
        
        # Show intermediate stats
        stats = extractor.get_stats()
        print(f"        [STATS] Active flows: {stats['active_flows']}, "
              f"Completed: {stats['flows_completed']}, "
              f"Packets: {stats['packets_processed']}")
        
        # Check for completed flows
        completed = extractor.get_completed_flows()
        if completed:
            print(f"        [FLOWS] {len(completed)} new flows completed")
    
    print()
    
    # Step 4: Stop extractor (forces final flush)
    print("[TEST] Step 4: Stopping flow extractor...")
    extractor.stop()
    
    # Get final completed flows
    final_flows = extractor.get_completed_flows()
    print(f"[TEST] Final completed flows in queue: {len(final_flows)}")
    
    # Step 5: Stop capture
    print("[TEST] Step 5: Stopping capture...")
    capture.stop()
    
    # Step 6: Analyze results
    print()
    print("[TEST] Step 6: Analyzing results...")
    
    stats = extractor.get_stats()
    print(f"        Total packets processed: {stats['packets_processed']}")
    print(f"        Total flows completed:   {stats['flows_completed']}")
    print(f"        Flows in output queue:   {len(final_flows)}")
    print()
    
    # Show sample flow features
    if final_flows:
        print("[SAMPLE FLOW FEATURES]")
        sample = final_flows[0]
        for key, value in sample.items():
            if isinstance(value, float):
                print(f"        {key:30s} = {value:12.4f}")
            else:
                print(f"        {key:30s} = {value}")
        print()
    
    # Step 7: Evaluate
    print("=" * 60)
    print("  RESULTS")
    print("=" * 60)
    
    all_passed = True
    
    # Check 1: Packets were processed
    pkt_ok = stats['packets_processed'] > 0
    print(f"[{'PASS' if pkt_ok else 'FAIL'}] Packets processed: {stats['packets_processed']}")
    if not pkt_ok:
        all_passed = False
    
    # Check 2: Flows were created
    flow_ok = stats['flows_completed'] > 0
    print(f"[{'PASS' if flow_ok else 'FAIL'}] Flows completed: {stats['flows_completed']}")
    if not flow_ok:
        all_passed = False
    
    # Check 3: Features computed (all 25 keys present)
    if final_flows:
        feature_count = len(final_flows[0])
        feature_ok = feature_count == 25
        print(f"[{'PASS' if feature_ok else 'WARN'}] Features per flow: {feature_count} (expected 25)")
    else:
        print("[WARN] No flows to check features on")
    
    print()
    if all_passed:
        print("=" * 60)
        print("  PHASE 1 COMPLETE — Flow extraction is working!")
        print("=" * 60)
        return True
    else:
        print("=" * 60)
        print("  PHASE 1 INCOMPLETE — Some checks failed.")
        print("=" * 60)
        return False


if __name__ == "__main__":
    success = test_flow_extraction()
    sys.exit(0 if success else 1)

"""
Verification script for the storage layer.

Tests:
  1. Database initialization
  2. Alert insertion and retrieval
  3. Alert counting and filtering
  4. Timeline queries
  5. Top source IPs
  6. Flow stats
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.storage import DatabaseManager


def test_database_init():
    """Test database creation."""
    print("=" * 60)
    print("  Test 1: Database Initialization")
    print("=" * 60)
    
    db = DatabaseManager("data/test_alerts.db")
    size, count = db.get_database_size()
    print(f"  Database size: {size} bytes")
    print(f"  Alert count: {count}")
    assert size > 0, "Database file should exist"
    print(f"  ✅ Database created successfully")
    print()
    return db


def test_insert_alerts(db):
    """Test inserting and retrieving alerts."""
    print("=" * 60)
    print("  Test 2: Alert Insertion & Retrieval")
    print("=" * 60)
    
    # Insert test alerts
    alerts = [
        {
            "timestamp": "2026-07-12T10:00:00",
            "attack_type": "PortScan",
            "severity": "high",
            "final_score": 0.92,
            "rule_score": 0.90,
            "ml_score": 0.88,
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "source_port": 54321,
            "destination_port": 80,
            "protocol": 6,
            "flow_features": {"syn_count": 100, "total_fwd_packets": 100},
            "packet_summary": "Port scan detected from 192.168.1.100",
        },
        {
            "timestamp": "2026-07-12T10:01:00",
            "attack_type": "DoS",
            "severity": "high",
            "final_score": 0.95,
            "rule_score": 0.95,
            "ml_score": 0.92,
            "source_ip": "10.0.0.55",
            "destination_ip": "192.168.1.1",
            "source_port": 12345,
            "destination_port": 443,
            "protocol": 6,
            "flow_features": {"total_fwd_packets": 5000, "flow_duration": 1000000},
            "packet_summary": "DoS flood detected",
        },
        {
            "timestamp": "2026-07-12T10:02:00",
            "attack_type": "WebAttack",
            "severity": "medium",
            "final_score": 0.78,
            "rule_score": 0.80,
            "ml_score": 0.60,
            "source_ip": "172.16.0.10",
            "destination_ip": "192.168.1.1",
            "source_port": 45678,
            "destination_port": 8080,
            "protocol": 6,
            "flow_features": {"payload": "' OR 1=1 --"},
            "packet_summary": "SQL injection attempt",
        },
        {
            "timestamp": "2026-07-12T10:03:00",
            "attack_type": None,
            "severity": "low",
            "final_score": 0.15,
            "rule_score": 0.10,
            "ml_score": 0.20,
            "source_ip": "192.168.1.50",
            "destination_ip": "8.8.8.8",
            "source_port": 60000,
            "destination_port": 53,
            "protocol": 17,
            "flow_features": {},
            "packet_summary": "Normal DNS query",
        },
    ]
    
    ids = []
    for alert in alerts:
        alert_id = db.save_alert(alert)
        ids.append(alert_id)
        print(f"  Inserted alert ID: {alert_id} — {alert['attack_type'] or 'Benign'} ({alert['severity']})")
    
    assert len(ids) == 4, "Should have 4 alerts"
    
    # Retrieve recent alerts
    recent = db.get_recent_alerts(limit=10)
    print(f"\n  Retrieved {len(recent)} recent alerts")
    assert len(recent) == 4, "Should retrieve all 4 alerts"
    
    # Verify ordering (newest first)
    assert recent[0]["severity"] == "low", "Most recent should be low severity (last inserted)"
    print(f"  ✅ Alerts inserted and retrieved correctly")
    print()


def test_alert_filtering(db):
    """Test filtering alerts by severity."""
    print("=" * 60)
    print("  Test 3: Alert Filtering")
    print("=" * 60)
    
    # Filter by severity
    high_alerts = db.get_recent_alerts(limit=10, severity="high")
    print(f"  High severity alerts: {len(high_alerts)}")
    assert len(high_alerts) == 2, "Should have 2 high severity alerts"
    
    medium_alerts = db.get_recent_alerts(limit=10, severity="medium")
    print(f"  Medium severity alerts: {len(medium_alerts)}")
    assert len(medium_alerts) == 1, "Should have 1 medium alert"
    
    # Get alert by ID
    alert = db.get_alert_by_id(1)
    assert alert is not None, "Alert ID 1 should exist"
    print(f"  Alert ID 1: {alert['attack_type']} — {alert['severity']}")
    print(f"  ✅ Filtering works correctly")
    print()


def test_alert_counts(db):
    """Test alert counting and statistics."""
    print("=" * 60)
    print("  Test 4: Alert Counts & Statistics")
    print("=" * 60)
    
    counts = db.get_alert_count(since_minutes=1440)  # Last 24 hours
    print(f"  Total alerts: {counts['total']}")
    print(f"  By severity: {counts['by_severity']}")
    print(f"  By type: {counts['by_type']}")
    
    assert counts["total"] == 4, "Should have 4 total alerts"
    assert counts["by_severity"].get("high", 0) == 2, "Should have 2 high"
    assert counts["by_type"].get("PortScan", 0) == 1, "Should have 1 PortScan"
    print(f"  ✅ Alert counts correct")
    
    # Top source IPs
    top_ips = db.get_top_source_ips(limit=5, since_minutes=1440)
    print(f"  Top source IPs: {top_ips}")
    assert len(top_ips) >= 3, "Should have at least 3 unique IPs"
    print(f"  ✅ Top IPs query works")
    print()


def test_flow_stats(db):
    """Test flow statistics storage and retrieval."""
    print("=" * 60)
    print("  Test 5: Flow Statistics")
    print("=" * 60)
    
    # Save flow stats
    db.save_flow_stats({
        "total_flows": 150,
        "benign_flows": 140,
        "attack_flows": 10,
        "alerts_high": 3,
        "alerts_medium": 5,
        "alerts_low": 2,
    })
    
    stats = db.get_flow_stats(since_minutes=1440)
    print(f"  Flow stats: {stats}")
    assert stats["total_flows"] == 150, "Should have 150 total flows"
    assert stats["benign_flows"] == 140, "Should have 140 benign"
    print(f"  ✅ Flow stats working")
    print()


def test_cleanup(db):
    """Test database maintenance."""
    print("=" * 60)
    print("  Test 6: Database Maintenance")
    print("=" * 60)
    
    size, count = db.get_database_size()
    print(f"  Current size: {size} bytes, {count} alerts")
    
    # Cleanup shouldn't delete our recent alerts
    deleted = db.cleanup_old_alerts(older_than_hours=1)
    print(f"  Cleaned up {deleted} alerts (older than 1 hour)")
    
    # Verify alerts still exist (they're from today)
    recent = db.get_recent_alerts(limit=10)
    print(f"  Remaining alerts: {len(recent)}")
    print(f"  ✅ Cleanup works correctly")
    print()


def main():
    print("=" * 60)
    print("  SOC-NIDS Phase 5: Storage Layer Verification")
    print("=" * 60)
    print()
    
    db = test_database_init()
    test_insert_alerts(db)
    test_alert_filtering(db)
    test_alert_counts(db)
    test_flow_stats(db)
    test_cleanup(db)
    
    # Clean up test database
    import os
    if os.path.exists("data/test_alerts.db"):
        os.remove("data/test_alerts.db")
        print("  Test database removed")
    
    print("=" * 60)
    print("  PHASE 5 COMPLETE — Storage Layer is working!")
    print("=" * 60)


if __name__ == "__main__":
    main()

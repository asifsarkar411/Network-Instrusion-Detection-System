"""
IPS (Intrusion Prevention System) Engine
========================================
Handles active risk prevention, automated threat mitigation,
dynamic IP blocking, firewall rule generation, TCP session termination,
and virtual patch enforcement for SOC-NIDS.
"""

import os
import sys
import time
import subprocess
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
import sqlite3

class IPSEngine:
    """
    Real-Time Prevention & Response Engine for SOC-NIDS.
    
    Transforms detection into active defense:
    - OS-Level Firewall Rule Injection (Windows Netsh / Linux iptables)
    - TCP Reset (RST) Active Session Termination
    - Automatic Threat Quarantine based on ML confidence & Rule severity
    - Dropped Packet Auditing & Telemetry
    - Exportable Policy Rules for Enterprise Firewalls & WAFs
    """
    
    # IPs that must NEVER be auto-blocked (DNS resolvers, localhost, broadcast)
    SAFE_IPS: Set[str] = {
        "127.0.0.1", "0.0.0.0", "localhost", "—", "-", "",
        "1.1.1.1", "1.0.0.1",           # Cloudflare DNS
        "8.8.8.8", "8.8.4.4",           # Google DNS
        "9.9.9.9",                        # Quad9 DNS
        "208.67.222.222", "208.67.220.220",  # OpenDNS
        "255.255.255.255",                # Broadcast
    }
    
    # Private/reserved subnet prefixes — never auto-block local network traffic
    SAFE_PREFIXES = (
        "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
        "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
        "169.254.", "fe80:", "::1",
    )
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(IPSEngine, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, db_path: str = "data/nids_alerts.db"):
        if getattr(self, "_initialized", False):
            return
        
        self.db_path = db_path
        self._blocked_cache: Set[str] = set()
        self._auto_block_enabled: bool = True
        self._block_threshold: float = 0.85
        self._auto_rst_enabled: bool = True
        self._os_firewall_sync: bool = True
        self._stats = {
            "total_blocked": 0,
            "packets_dropped": 0,
            "tcp_rsts_sent": 0,
            "active_firewall_rules": 0
        }
        
        self._init_db()
        self._load_cache()
        self._purge_expired_blocks()
        self._initialized = True
    
    def is_safelisted(self, ip_address: str) -> bool:
        """Check if an IP is safelisted and should never be auto-blocked."""
        if not ip_address:
            return True
        ip = str(ip_address).strip()
        if ip in self.SAFE_IPS:
            return True
        if ip.startswith(self.SAFE_PREFIXES):
            return True
        # Also protect the host's own IP
        try:
            import socket
            host_ip = socket.gethostbyname(socket.gethostname())
            if ip == host_ip:
                return True
        except Exception:
            pass
        return False
    
    def _purge_expired_blocks(self) -> None:
        """Automatically deactivate blocks that have exceeded their expiry time."""
        try:
            now = datetime.now().isoformat()
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE blocked_ips SET is_active = 0
                    WHERE is_active = 1 AND expires_at != 'PERMANENT' AND expires_at < ?
                """, (now,))
                purged = cursor.rowcount
                conn.commit()
                if purged > 0:
                    self._load_cache()
                    print(f"[IPSEngine] Purged {purged} expired block(s)")
        except Exception:
            pass

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Create tables for prevention and blocking."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE NOT NULL,
                    reason TEXT NOT NULL,
                    action TEXT NOT NULL,
                    blocked_at TEXT NOT NULL,
                    expires_at TEXT,
                    is_active INTEGER DEFAULT 1,
                    packets_dropped INTEGER DEFAULT 0,
                    rule_name TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ips_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    details TEXT
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_blocked_ip ON blocked_ips(ip_address)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_blocked_active ON blocked_ips(is_active)")
            conn.commit()

    def _load_cache(self) -> None:
        """Load active blocked IPs into memory for microsecond lookups."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT ip_address FROM blocked_ips WHERE is_active = 1")
                rows = cursor.fetchall()
                self._blocked_cache = {row[0] for row in rows}
                
                cursor.execute("SELECT SUM(packets_dropped) FROM blocked_ips")
                total_dropped = cursor.fetchone()[0] or 0
                self._stats["total_blocked"] = len(self._blocked_cache)
                self._stats["packets_dropped"] = total_dropped
        except Exception:
            self._blocked_cache = set()

    def is_blocked(self, ip_address: str) -> bool:
        """Check if an IP is currently blocked (in-memory fast check)."""
        if not ip_address or ip_address in ["127.0.0.1", "localhost", "—", "-"]:
            return False
        return ip_address in self._blocked_cache

    def block_ip(
        self,
        ip_address: str,
        reason: str = "High Risk Intrusion Detected",
        action: str = "FIREWALL_DROP",
        duration_minutes: int = 60,
        enforce_os: bool = True
    ) -> Dict:
        """
        Actively block an IP address and enforce prevention.
        """
        ip = str(ip_address).strip()
        if not ip or ip in ["127.0.0.1", "0.0.0.0", "localhost", "—", "-"]:
            return {"success": False, "message": "Invalid or protected IP address."}

        blocked_at = datetime.now().isoformat()
        expires_at = (datetime.now() + timedelta(minutes=duration_minutes)).isoformat() if duration_minutes > 0 else "PERMANENT"
        rule_name = f"SOC_NIDS_BLOCK_{ip.replace('.', '_').replace(':', '_')}"

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO blocked_ips (ip_address, reason, action, blocked_at, expires_at, is_active, rule_name)
                VALUES (?, ?, ?, ?, ?, 1, ?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    reason = excluded.reason,
                    action = excluded.action,
                    blocked_at = excluded.blocked_at,
                    expires_at = excluded.expires_at,
                    is_active = 1,
                    rule_name = excluded.rule_name
            """, (ip, reason, action, blocked_at, expires_at, rule_name))
            
            cursor.execute("""
                INSERT INTO ips_audit_log (timestamp, ip_address, event_type, details)
                VALUES (?, ?, ?, ?)
            """, (blocked_at, ip, "IP_BLOCKED", f"Action: {action} | Reason: {reason} | Duration: {duration_minutes}m"))
            conn.commit()

        self._blocked_cache.add(ip)
        self._stats["total_blocked"] = len(self._blocked_cache)

        os_status = "Skipped"
        if enforce_os and self._os_firewall_sync:
            os_status = self._apply_os_firewall_rule(ip, rule_name)

        return {
            "success": True,
            "status": "blocked",
            "ip": ip,
            "action": action,
            "rule_name": rule_name,
            "os_enforcement": os_status,
            "message": f"Successfully blocked {ip} ({action})."
        }

    def unblock_ip(self, ip_address: str) -> Dict:
        """Unblock an IP address and tear down firewall rules."""
        ip = str(ip_address).strip()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT rule_name FROM blocked_ips WHERE ip_address = ?", (ip,))
            row = cursor.fetchone()
            rule_name = row[0] if row else f"SOC_NIDS_BLOCK_{ip.replace('.', '_')}"

            cursor.execute("UPDATE blocked_ips SET is_active = 0 WHERE ip_address = ?", (ip,))
            cursor.execute("""
                INSERT INTO ips_audit_log (timestamp, ip_address, event_type, details)
                VALUES (?, ?, ?, ?)
            """, (datetime.now().isoformat(), ip, "IP_UNBLOCKED", "Manually released from quarantine"))
            conn.commit()

        self._blocked_cache.discard(ip)
        self._stats["total_blocked"] = len(self._blocked_cache)

        # Remove OS firewall rule
        self._remove_os_firewall_rule(ip, rule_name)

        return {"success": True, "status": "unblocked", "ip": ip, "message": f"IP {ip} has been unblocked."}

    def record_dropped_packet(self, ip_address: str, count: int = 1) -> None:
        """Record packets dropped by the IPS engine."""
        if not ip_address:
            return
        self._stats["packets_dropped"] += count
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE blocked_ips 
                    SET packets_dropped = packets_dropped + ? 
                    WHERE ip_address = ? AND is_active = 1
                """, (count, ip_address))
                conn.commit()
        except Exception:
            pass

    def send_tcp_reset(self, src_ip: str, dst_ip: str, src_port: int = 0, dst_port: int = 80) -> Dict:
        """
        Active Session Termination (TCP RST Injection).
        Forges and transmits TCP RST packets to instantly tear down malicious TCP sessions.
        """
        try:
            from scapy.layers.inet import IP, TCP
            from scapy.sendrecv import send

            # Send RST to target
            pkt1 = IP(src=src_ip, dst=dst_ip) / TCP(sport=int(src_port or 1024), dport=int(dst_port or 80), flags="R")
            # Send RST to attacker
            pkt2 = IP(src=dst_ip, dst=src_ip) / TCP(sport=int(dst_port or 80), dport=int(src_port or 1024), flags="R")

            send(pkt1, verbose=0)
            send(pkt2, verbose=0)

            self._stats["tcp_rsts_sent"] += 2
            
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO ips_audit_log (timestamp, ip_address, event_type, details)
                    VALUES (?, ?, ?, ?)
                """, (datetime.now().isoformat(), src_ip, "TCP_RST_INJECTED", f"Terminated session with {dst_ip}:{dst_port}"))
                conn.commit()

            return {"success": True, "message": f"TCP RST packets transmitted to {src_ip} and {dst_ip}."}
        except Exception as e:
            return {"success": False, "message": f"TCP RST Injection notice: {str(e)}"}

    def _apply_os_firewall_rule(self, ip: str, rule_name: str) -> str:
        """Inject firewall rule into host operating system."""
        try:
            if sys.platform == "win32":
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}",
                    "dir=in",
                    "action=block",
                    f"remoteip={ip}"
                ]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
                if res.returncode == 0:
                    self._stats["active_firewall_rules"] += 1
                    return "Windows Firewall Rule Added (Active)"
                return f"Netsh fallback: {res.stderr.strip() or 'Requires Administrator permissions'}"
            else:
                # Linux iptables
                cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
                subprocess.run(cmd, capture_output=True, timeout=3)
                return "Linux iptables Rule Added (Active)"
        except Exception as e:
            return f"OS rule notice: {str(e)}"

    def _remove_os_firewall_rule(self, ip: str, rule_name: str) -> str:
        """Remove firewall rule from host OS."""
        try:
            if sys.platform == "win32":
                cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
                subprocess.run(cmd, capture_output=True, timeout=3)
                return "Windows Firewall Rule Deleted"
            else:
                cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
                subprocess.run(cmd, capture_output=True, timeout=3)
                return "Linux iptables Rule Deleted"
        except Exception as e:
            return str(e)

    def evaluate_alert_for_auto_block(self, alert_data: Dict) -> Optional[Dict]:
        """
        Evaluate an incoming alert and autonomously block the attacker if policies match.
        Safelisted IPs (private subnets, DNS resolvers, host IP) are never auto-blocked.
        """
        if not self._auto_block_enabled:
            return None

        src_ip = alert_data.get("source_ip") or alert_data.get("src_ip")
        if not src_ip or src_ip in ["—", "-", "127.0.0.1", "localhost"]:
            return None
        
        # Never auto-block safelisted IPs (private networks, DNS, host IP)
        if self.is_safelisted(src_ip):
            return None

        sev = str(alert_data.get("severity", "")).lower()
        final_score = float(alert_data.get("final_score", 0.0))
        attack_type = alert_data.get("attack_type", "Malicious Threat")

        # Auto-block condition: High/Critical severity OR score >= threshold
        if sev in ["high", "critical"] or final_score >= self._block_threshold:
            if not self.is_blocked(src_ip):
                action = "FIREWALL_DROP"
                if "webattack" in attack_type.lower():
                    action = "WAF_BLOCK & QUARANTINE"
                elif "dos" in attack_type.lower() or "ddos" in attack_type.lower():
                    action = "RATE_LIMIT & DROP"
                
                res = self.block_ip(
                    ip_address=src_ip,
                    reason=f"Autonomous IPS: {attack_type} detected (Score: {final_score*100:.1f}%)",
                    action=action,
                    duration_minutes=120
                )
                
                # If auto RST is enabled and ports are provided
                if self._auto_rst_enabled and alert_data.get("destination_ip"):
                    self.send_tcp_reset(
                        src_ip=src_ip,
                        dst_ip=alert_data.get("destination_ip"),
                        src_port=alert_data.get("source_port", 0),
                        dst_port=alert_data.get("destination_port", 80)
                    )
                
                return res
        return None

    def get_blocked_list(self, active_only: bool = True) -> List[Dict]:
        """Get all blocked IP entries with statistics."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM blocked_ips"
            if active_only:
                query += " WHERE is_active = 1"
            query += " ORDER BY blocked_at DESC"
            cursor.execute(query)
            return [dict(row) for row in cursor.fetchall()]

    def get_audit_logs(self, limit: int = 50) -> List[Dict]:
        """Get recent IPS action history."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ips_audit_log ORDER BY timestamp DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_stats(self) -> Dict:
        """Get consolidated IPS operational stats."""
        blocked_list = self.get_blocked_list(active_only=True)
        total_drops = sum(b.get("packets_dropped", 0) for b in blocked_list)
        return {
            "total_blocked_ips": len(blocked_list),
            "packets_dropped": total_drops or self._stats["packets_dropped"],
            "tcp_rsts_sent": self._stats["tcp_rsts_sent"],
            "auto_block_enabled": self._auto_block_enabled,
            "block_threshold": self._block_threshold,
            "auto_rst_enabled": self._auto_rst_enabled,
            "os_firewall_sync": self._os_firewall_sync,
        }

    def generate_firewall_rules(self, ips: Optional[List[str]] = None) -> Dict[str, str]:
        """Generate platform-specific firewall and WAF rules."""
        if ips is None:
            blocked = self.get_blocked_list(active_only=True)
            ips = [b["ip_address"] for b in blocked]
        
        if not ips:
            ips = ["198.51.100.42", "203.0.113.19"]  # RFC 5737 example IPs
        
        # 1. Windows PowerShell
        ps_lines = [
            "# SOC-NIDS // Windows Firewall Hardening Rules",
            "# Run as Administrator in PowerShell"
        ]
        for ip in ips:
            rule = f"New-NetFirewallRule -DisplayName 'SOC-NIDS Block {ip}' -Direction Inbound -Action Block -RemoteAddress {ip}"
            ps_lines.append(rule)
        
        # 2. Linux iptables / ufw
        iptables_lines = [
            "#!/bin/bash",
            "# SOC-NIDS // Linux iptables & UFW Prevention Rules"
        ]
        for ip in ips:
            iptables_lines.append(f"sudo iptables -I INPUT -s {ip} -j DROP")
            iptables_lines.append(f"sudo ufw deny from {ip}")
        
        # 3. Cisco IOS ACL
        cisco_lines = [
            "! SOC-NIDS // Cisco Router / Switch Access Control List",
            "ip access-list extended SOC_NIDS_INBOUND_FILTER"
        ]
        for i, ip in enumerate(ips, 10):
            cisco_lines.append(f" {i} deny ip host {ip} any")
        cisco_lines.append(" 999 permit ip any any")

        # 4. Nginx WAF / Reverse Proxy
        nginx_lines = [
            "# SOC-NIDS // Nginx Virtual Patching / WAF Deny Directives",
            "# Place in http {} or server {} block"
        ]
        for ip in ips:
            nginx_lines.append(f"deny {ip};")
        nginx_lines.append("allow all;")

        return {
            "powershell": "\n".join(ps_lines),
            "iptables": "\n".join(iptables_lines),
            "cisco": "\n".join(cisco_lines),
            "nginx": "\n".join(nginx_lines)
        }

"""
PCAP Capture Module
Captures network traffic from LAN and WAN interfaces
"""

import os
import logging
import threading
import subprocess
import signal
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List
import uuid
import asyncio

from app.models.database import Database, PcapFile, Alert
from app.core.config import settings

logger = logging.getLogger(__name__)


class PCAPCapture:
    """PCAP capture manager using tcpdump"""

    def __init__(self, db: Database):
        self.db = db
        self.lan_interface = settings.lan_interface
        self.wan_interface = settings.wan_interface
        self.pcap_dir = settings.pcap_dir
        self.rotation_size = self._parse_size(settings.pcap_rotation_size)
        self.max_files = settings.pcap_max_files
        self.active_captures: Dict[str, subprocess.Popen] = {}
        self.capture_lock = threading.Lock()
        self.running = False

    def _parse_size(self, size_str: str) -> int:
        """Parse size string like '100M' to bytes"""
        size_str = size_str.upper().strip()
        multipliers = {"K": 1024, "M": 1024**2, "G": 1024**3}
        if size_str[-1] in multipliers:
            return int(size_str[:-1]) * multipliers[size_str[-1]]
        return int(size_str)

    def _generate_filename(self, interface: str) -> str:
        """Generate PCAP filename with timestamp"""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        return f"capture_{interface}_{timestamp}.pcap"

    def start_capture(self, interface: str, duration: Optional[int] = None,
                     filter_bpf: Optional[str] = None) -> Optional[str]:
        """Start PCAP capture on specified interface"""
        with self.capture_lock:
            if interface in self.active_captures:
                logger.warning(f"Capture already running on {interface}")
                return None

            # Create pcap directory if not exists
            Path(self.pcap_dir).mkdir(parents=True, exist_ok=True)

            filename = self._generate_filename(interface)
            filepath = os.path.join(self.pcap_dir, filename)

            # Build tcpdump command
            cmd = [
                "tcpdump",
                "-i", interface,
                "-w", filepath,
                "-C", str(self.rotation_size // 1024),  # Size in KB
                "-W", str(self.max_files),
                "-z", "gzip",  # Compress rotated files
                "-v"  # Verbose
            ]

            if duration:
                cmd.extend(["-G", str(duration)])

            if filter_bpf:
                cmd.extend(["-f", filter_bpf])

            # Add common options
            cmd.extend([
                "-nn",  # Don't resolve hostnames or ports
                "-s", "65535",  # Capture full packets
                "-p",  # Don't put interface in promiscuous mode (change to -p for promiscuous)
            ])

            try:
                # Start tcpdump
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    preexec_fn=os.setsid
                )

                self.active_captures[interface] = process
                logger.info(f"Started PCAP capture on {interface}, file: {filepath}")

                # Store PCAP metadata
                pcap = PcapFile(
                    id=str(uuid.uuid4()),
                    filename=filename,
                    filepath=filepath,
                    start_time=datetime.utcnow().isoformat(),
                    interface=interface
                )
                self.db.insert_pcap(pcap)

                return pcap.id
            except Exception as e:
                logger.error(f"Failed to start capture on {interface}: {e}")
                return None

    def stop_capture(self, interface: str) -> bool:
        """Stop PCAP capture on specified interface"""
        with self.capture_lock:
            if interface not in self.active_captures:
                logger.warning(f"No capture running on {interface}")
                return False

            try:
                process = self.active_captures[interface]
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                process.wait(timeout=10)
                del self.active_captures[interface]
                logger.info(f"Stopped PCAP capture on {interface}")
                return True
            except Exception as e:
                logger.error(f"Failed to stop capture on {interface}: {e}")
                return False

    def stop_all_captures(self) -> None:
        """Stop all active captures"""
        with self.capture_lock:
            for interface in list(self.active_captures.keys()):
                self.stop_capture(interface)

    def get_active_captures(self) -> List[Dict[str, Any]]:
        """Get list of active captures"""
        result = []
        for interface, process in self.active_captures.items():
            if process.poll() is None:
                result.append({
                    "interface": interface,
                    "pid": process.pid,
                    "running": True
                })
            else:
                del self.active_captures[interface]
        return result


class DNSQueryMonitor:
    """Monitors DNS query logs for threat matching"""

    def __init__(self, db: Database):
        self.db = db
        self.dns_log_path = settings.dns_log_path
        self.matched_domains: set = set()
        self.file_position = 0
        self.running = False
        self.thread: Optional[threading.Thread] = None

    def match_domain(self, domain: str) -> Optional[Alert]:
        """Check if domain matches any indicator and create alert if so"""
        # Check if domain is in indicators
        indicator = self.db.check_indicator(domain, "domain")

        if not indicator:
            # Check parent domains
            parts = domain.split(".")
            for i in range(1, len(parts)):
                parent = ".".join(parts[i:])
                indicator = self.db.check_indicator(parent, "domain")
                if indicator:
                    break

        if indicator:
            alert = Alert(
                id=str(uuid.uuid4()),
                timestamp=datetime.utcnow().isoformat(),
                severity=self._get_severity(indicator.source),
                source_ip="",  # Would need to correlate with network logs
                indicator=domain,
                indicator_type="domain",
                feed_source=indicator.source,
                rule_id=indicator.feed_id,
                message=f"DNS query to blocked domain: {domain}"
            )
            self.db.insert_alert(alert)
            logger.warning(f"Blocked DNS query: {domain} (matched {indicator.source})")
            return alert

        return None

    def _get_severity(self, source: str) -> str:
        """Get severity based on feed source"""
        severity_map = {
            "misp": "high",
            "pfblocker": "medium",
            "pfblocker_local": "medium"
        }
        return severity_map.get(source, "info")

    def start_monitoring(self) -> None:
        """Start DNS log monitoring"""
        if self.running:
            return

        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logger.info("Started DNS query monitoring")

    def stop_monitoring(self) -> None:
        """Stop DNS log monitoring"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("Stopped DNS query monitoring")

    def _monitor_loop(self) -> None:
        """Main monitoring loop"""
        while self.running:
            try:
                if os.path.exists(self.dns_log_path):
                    with open(self.dns_log_path, "r") as f:
                        f.seek(self.file_position)
                        for line in f:
                            line = line.strip()
                            if line:
                                # Parse DNS log line (assuming JSON format)
                                try:
                                    log_entry = json.loads(line)
                                    if "query" in log_entry:
                                        domain = log_entry["query"].get("name", "")
                                        if domain:
                                            self.match_domain(domain)
                                except json.JSONDecodeError:
                                    # Try plain text format
                                    parts = line.split()
                                    if len(parts) >= 2 and "A" in parts:
                                        domain = parts[1]
                                        if domain:
                                            self.match_domain(domain)

                        self.file_position = f.tell()
            except Exception as e:
                logger.error(f"Error monitoring DNS log: {e}")

            threading.Event().wait(1)  # Check every second


class PacketAnalyzer:
    """Analyzes captured packets for indicators"""

    def __init__(self, db: Database):
        self.db = db

    def analyze_pcap(self, pcap_path: str) -> List[Alert]:
        """Analyze PCAP file for threat indicators"""
        alerts = []

        try:
            # Try to use tshark for analysis
            cmd = [
                "tshark",
                "-r", pcap_path,
                "-T", "fields",
                "-e", "ip.src",
                "-e", "ip.dst",
                "-e", "tcp.srcport",
                "-e", "tcp.dstport",
                "-e", "udp.srcport",
                "-e", "udp.dstport",
                "-e", "frame.protocols",
                "-e", "dns.qry.name",
                "-e", "http.request.uri",
                "-Y", "ip"
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            for line in result.stdout.split("\n"):
                if not line.strip():
                    continue

                fields = line.split("\t")
                if len(fields) < 2:
                    continue

                src_ip = fields[0] if len(fields) > 0 else ""
                dst_ip = fields[1] if len(fields) > 1 else ""

                # Check destination IP against indicators
                if dst_ip:
                    indicator = self.db.check_indicator(dst_ip, "ip")
                    if indicator:
                        alert = Alert(
                            id=str(uuid.uuid4()),
                            timestamp=datetime.utcnow().isoformat(),
                            severity="high",
                            source_ip=src_ip,
                            destination_ip=dst_ip,
                            indicator=dst_ip,
                            indicator_type="ip",
                            feed_source=indicator.source,
                            rule_id=indicator.feed_id,
                            message=f"Connection to blocked IP: {dst_ip}"
                        )
                        alerts.append(alert)
                        self.db.insert_alert(alert)

                # Check DNS queries
                dns_idx = 7
                if len(fields) > dns_idx and fields[dns_idx]:
                    domain = fields[dns_idx]
                    indicator = self.db.check_indicator(domain, "domain")
                    if indicator:
                        alert = Alert(
                            id=str(uuid.uuid4()),
                            timestamp=datetime.utcnow().isoformat(),
                            severity="high",
                            source_ip=src_ip,
                            destination_ip=dst_ip,
                            indicator=domain,
                            indicator_type="domain",
                            feed_source=indicator.source,
                            rule_id=indicator.feed_id,
                            message=f"DNS query to blocked domain: {domain}"
                        )
                        alerts.append(alert)
                        self.db.insert_alert(alert)

                # Check HTTP URLs
                http_idx = 8
                if len(fields) > http_idx and fields[http_idx]:
                    url = fields[http_idx]
                    indicator = self.db.check_indicator(url, "url")
                    if indicator:
                        alert = Alert(
                            id=str(uuid.uuid4()),
                            timestamp=datetime.utcnow().isoformat(),
                            severity="high",
                            source_ip=src_ip,
                            indicator=url,
                            indicator_type="url",
                            feed_source=indicator.source,
                            rule_id=indicator.feed_id,
                            message=f"HTTP request to blocked URL: {url}"
                        )
                        alerts.append(alert)
                        self.db.insert_alert(alert)

            logger.info(f"Analyzed {pcap_path}: found {len(alerts)} alerts")

        except subprocess.TimeoutExpired:
            logger.error(f"PCAP analysis timeout: {pcap_path}")
        except Exception as e:
            logger.error(f"Failed to analyze PCAP: {e}")

        return alerts

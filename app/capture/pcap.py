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

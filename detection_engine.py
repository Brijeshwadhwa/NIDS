"""
NIDS Detection Engine - Signature-based intrusion detection.
"""

import logging
import time
from collections import defaultdict
from typing import Callable, Optional

import config

logger = logging.getLogger(__name__)


def _now() -> float:
    """Current time in seconds (for sliding windows)."""
    return time.time()


class DetectionEngine:
    """
    Signature-based detection for:
    - SYN Flood
    - Port Scan
    - ICMP Flood
    - ARP Spoofing
    - Brute Force (auth port probes)
    """

    def __init__(self, on_alert: Callable[[str, str, str], None]):
        """
        Args:
            on_alert: Callback(attack_type, source_ip, description) when alert is raised.
        """
        self.on_alert = on_alert
        self._syn_times: dict[str, list[float]] = defaultdict(list)
        self._port_scan: dict[str, dict[int, float]] = defaultdict(dict)  # ip -> {port: time}
        self._icmp_times: dict[str, list[float]] = defaultdict(list)
        self._arp_ip_to_mac: dict[str, dict[str, float]] = defaultdict(dict)  # ip -> {mac: time}
        self._brute_force: dict[str, list[float]] = defaultdict(list)
        self._last_cleanup = _now()

    def _cleanup_old(self) -> None:
        """Remove entries older than the largest window to prevent unbounded growth."""
        now = _now()
        if now - self._last_cleanup < config.CLEANUP_INTERVAL_SEC:
            return
        self._last_cleanup = now
        max_window = max(
            config.SYN_FLOOD_WINDOW_SEC,
            config.PORT_SCAN_WINDOW_SEC,
            config.ICMP_FLOOD_WINDOW_SEC,
            config.ARP_SPOOF_WINDOW_SEC,
            config.BRUTE_FORCE_WINDOW_SEC,
        )
        cutoff = now - max_window - 10

        for key in list(self._syn_times):
            self._syn_times[key] = [t for t in self._syn_times[key] if t > cutoff]
            if not self._syn_times[key]:
                del self._syn_times[key]

        for ip in list(self._port_scan):
            self._port_scan[ip] = {p: t for p, t in self._port_scan[ip].items() if t > cutoff}
            if not self._port_scan[ip]:
                del self._port_scan[ip]

        for key in list(self._icmp_times):
            self._icmp_times[key] = [t for t in self._icmp_times[key] if t > cutoff]
            if not self._icmp_times[key]:
                del self._icmp_times[key]

        for ip in list(self._arp_ip_to_mac):
            self._arp_ip_to_mac[ip] = {m: t for m, t in self._arp_ip_to_mac[ip].items() if t > cutoff}
            if not self._arp_ip_to_mac[ip]:
                del self._arp_ip_to_mac[ip]

        for key in list(self._brute_force):
            self._brute_force[key] = [t for t in self._brute_force[key] if t > cutoff]
            if not self._brute_force[key]:
                del self._brute_force[key]

    def check_syn_flood(self, src_ip: str) -> None:
        """Record SYN and check for SYN flood."""
        now = _now()
        cutoff = now - config.SYN_FLOOD_WINDOW_SEC
        self._syn_times[src_ip].append(now)
        self._syn_times[src_ip] = [t for t in self._syn_times[src_ip] if t > cutoff]
        if len(self._syn_times[src_ip]) >= config.SYN_FLOOD_THRESHOLD:
            self.on_alert(
                "SYN Flood",
                src_ip,
                f"High volume of SYN packets ({len(self._syn_times[src_ip])}) in {config.SYN_FLOOD_WINDOW_SEC}s",
            )
            self._syn_times[src_ip].clear()

    def check_port_scan(self, src_ip: str, dst_port: int) -> None:
        """Record destination port and check for port scan."""
        now = _now()
        cutoff = now - config.PORT_SCAN_WINDOW_SEC
        self._port_scan[src_ip][dst_port] = now
        self._port_scan[src_ip] = {p: t for p, t in self._port_scan[src_ip].items() if t > cutoff}
        if len(self._port_scan[src_ip]) >= config.PORT_SCAN_THRESHOLD:
            self.on_alert(
                "Port Scan",
                src_ip,
                f"Multiple distinct ports targeted ({len(self._port_scan[src_ip])}) in {config.PORT_SCAN_WINDOW_SEC}s",
            )
            self._port_scan[src_ip].clear()

    def check_icmp_flood(self, src_ip: str) -> None:
        """Record ICMP and check for ICMP flood."""
        now = _now()
        cutoff = now - config.ICMP_FLOOD_WINDOW_SEC
        self._icmp_times[src_ip].append(now)
        self._icmp_times[src_ip] = [t for t in self._icmp_times[src_ip] if t > cutoff]
        if len(self._icmp_times[src_ip]) >= config.ICMP_FLOOD_THRESHOLD:
            self.on_alert(
                "ICMP Flood",
                src_ip,
                f"Excessive ICMP packets ({len(self._icmp_times[src_ip])}) in {config.ICMP_FLOOD_WINDOW_SEC}s",
            )
            self._icmp_times[src_ip].clear()

    def check_arp_spoofing(self, ip: str, mac: str) -> None:
        """Record ARP reply (IP -> MAC) and check for multiple MACs for same IP."""
        now = _now()
        cutoff = now - config.ARP_SPOOF_WINDOW_SEC
        self._arp_ip_to_mac[ip][mac] = now
        self._arp_ip_to_mac[ip] = {m: t for m, t in self._arp_ip_to_mac[ip].items() if t > cutoff}
        if len(self._arp_ip_to_mac[ip]) >= config.ARP_SPOOF_THRESHOLD:
            self.on_alert(
                "ARP Spoofing",
                ip,
                f"Multiple MAC addresses claiming IP ({len(self._arp_ip_to_mac[ip])} different MACs)",
            )
            self._arp_ip_to_mac[ip].clear()

    def check_brute_force(self, src_ip: str, dst_port: int) -> None:
        """Record connection to auth port and check for brute force pattern."""
        if dst_port not in config.BRUTE_FORCE_PORTS:
            return
        now = _now()
        cutoff = now - config.BRUTE_FORCE_WINDOW_SEC
        self._brute_force[src_ip].append(now)
        self._brute_force[src_ip] = [t for t in self._brute_force[src_ip] if t > cutoff]
        if len(self._brute_force[src_ip]) >= config.BRUTE_FORCE_THRESHOLD:
            self.on_alert(
                "Brute Force",
                src_ip,
                f"Multiple connection attempts to auth port {dst_port} ({len(self._brute_force[src_ip])}) in {config.BRUTE_FORCE_WINDOW_SEC}s",
            )
            self._brute_force[src_ip].clear()

    def process_packet(self, packet) -> None:
        """
        Process a Scapy packet and run relevant detectors.
        Expects packet to have been validated (has IP or ARP).
        """
        self._cleanup_old()

        # ARP
        if packet.haslayer("ARP"):
            arp = packet["ARP"]
            if arp.op == 2:  # is-at (reply)
                ip = arp.psrc
                mac = arp.hwsrc
                if ip and mac:
                    self.check_arp_spoofing(ip, mac)
            return

        # IP
        if not packet.haslayer("IP"):
            return
        src_ip = packet["IP"].src

        # ICMP
        if packet.haslayer("ICMP"):
            self.check_icmp_flood(src_ip)
            return

        # TCP
        if packet.haslayer("TCP"):
            tcp = packet["TCP"]
            if tcp.flags == "S":  # SYN
                self.check_syn_flood(src_ip)
            dport = tcp.dport
            if dport:
                self.check_port_scan(src_ip, dport)
            self.check_brute_force(src_ip, dport)
            return

        # UDP - can be used for port scan detection too
        if packet.haslayer("UDP"):
            dport = packet["UDP"].dport
            if dport:
                self.check_port_scan(src_ip, dport)

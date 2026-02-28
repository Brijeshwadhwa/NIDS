"""
NIDS Packet Sniffer - Scapy-based capture and stats collection.
"""

import logging
from typing import Callable, Optional

import config

logger = logging.getLogger(__name__)

# Lazy import to avoid requiring root on import
_scapy = None

def _get_scapy():
    global _scapy
    if _scapy is None:
        try:
            from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
            _scapy = {"sniff": sniff, "IP": IP, "TCP": TCP, "UDP": UDP, "ICMP": ICMP, "ARP": ARP}
        except ImportError as e:
            raise ImportError("Scapy is required. Install with: pip install scapy") from e
    return _scapy


class PacketSniffer:
    """
    Sniffs packets on the default interface, runs detection engine,
    and updates shared stats (packet count, protocol distribution).
    """

    def __init__(
        self,
        detection_callback: Callable,
        on_packet_count: Optional[Callable[[int], None]] = None,
        on_protocol_count: Optional[Callable[[str], None]] = None,
    ):
        """
        Args:
            detection_callback: Called with each packet for detection (e.g. engine.process_packet).
            on_packet_count: Optional callback to increment total packet count (receives delta 1).
            on_protocol_count: Optional callback(protocol_name) to update protocol distribution.
        """
        self.detection_callback = detection_callback
        self.on_packet_count = on_packet_count or (lambda _: None)
        self.on_protocol_count = on_protocol_count or (lambda _: None)
        self._stop_event = None
        self._sniff_thread = None

    def _get_protocol(self, packet) -> str:
        """Determine protocol name for distribution."""
        s = _get_scapy()
        if packet.haslayer(s["ARP"]):
            return "ARP"
        if packet.haslayer(s["ICMP"]):
            return "ICMP"
        if packet.haslayer(s["TCP"]):
            return "TCP"
        if packet.haslayer(s["UDP"]):
            return "UDP"
        return "Other"

    def _process_packet(self, packet) -> None:
        """Process a single packet: stats + detection."""
        try:
            self.on_packet_count(1)
            proto = self._get_protocol(packet)
            self.on_protocol_count(proto)
            self.detection_callback(packet)
        except Exception as e:
            logger.debug("Error processing packet: %s", e)

    def _run_sniff(self) -> None:
        """Run Scapy sniff in a loop until stop is requested."""
        s = _get_scapy()
        try:
            s["sniff"](
                prn=self._process_packet,
                store=False,
                filter=config.SNIFF_FILTER,
                iface=config.SNIFF_INTERFACE,
                stop_filter=lambda _: self._stop_event.is_set() if self._stop_event else False,
            )
        except Exception as e:
            logger.exception("Sniffer error: %s", e)
        logger.info("Sniffer stopped.")

    def start(self) -> None:
        """Start sniffing in a background thread."""
        import threading
        if self._sniff_thread is not None and self._sniff_thread.is_alive():
            logger.warning("Sniffer already running.")
            return
        self._stop_event = threading.Event()
        self._sniff_thread = threading.Thread(target=self._run_sniff, daemon=True)
        self._sniff_thread.start()
        logger.info("Sniffer started.")

    def stop(self) -> None:
        """Signal sniffer to stop."""
        if self._stop_event:
            self._stop_event.set()
        self._stop_event = None
        if self._sniff_thread:
            self._sniff_thread.join(timeout=5)
            self._sniff_thread = None
        logger.info("Sniffer stop requested.")

    def is_running(self) -> bool:
        """Return True if sniffer thread is active."""
        return self._sniff_thread is not None and self._sniff_thread.is_alive()

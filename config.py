"""
NIDS Configuration - Thresholds and settings for intrusion detection.
"""

import os

# Base directory for the project
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Database
DATABASE_PATH = os.path.join(BASE_DIR, "nids_alerts.db")

# Sniffing
SNIFF_INTERFACE = None  # None = default interface
SNIFF_FILTER = "ip or arp"  # BPF filter

# Detection thresholds
SYN_FLOOD_THRESHOLD = 50       # SYN packets from same IP in window
SYN_FLOOD_WINDOW_SEC = 5       # Time window in seconds

PORT_SCAN_THRESHOLD = 15       # Distinct ports from same IP in window
PORT_SCAN_WINDOW_SEC = 10      # Time window in seconds

ICMP_FLOOD_THRESHOLD = 100     # ICMP packets from same IP in window
ICMP_FLOOD_WINDOW_SEC = 5      # Time window in seconds

ARP_SPOOF_THRESHOLD = 3        # Different MACs claiming same IP
ARP_SPOOF_WINDOW_SEC = 10      # Time window in seconds

BRUTE_FORCE_PORTS = (21, 22, 23, 3306, 5432)  # FTP, SSH, Telnet, MySQL, PostgreSQL
BRUTE_FORCE_THRESHOLD = 10     # Connection attempts to auth ports from same IP
BRUTE_FORCE_WINDOW_SEC = 30    # Time window in seconds

# Sliding window cleanup interval (seconds)
CLEANUP_INTERVAL_SEC = 60

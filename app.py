"""
NIDS Web Application - Flask server with dashboard and API.
"""

import logging
import threading
from collections import deque
from datetime import datetime

from flask import Flask, jsonify, render_template, request

import config
from database import Database
from detection_engine import DetectionEngine
from packet_sniffer import PacketSniffer

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App and shared state (thread-safe)
# ---------------------------------------------------------------------------
app = Flask(__name__)
_lock = threading.Lock()
_total_packets = 0
_total_alerts = 0
_protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "Other": 0}
_recent_alerts = deque(maxlen=100)  # Last 100 for live feed
_sniffer = None
_db = None
_engine = None


def _on_alert(attack_type: str, source_ip: str, description: str) -> None:
    """On detection: save to DB, update counters, print, add to live feed."""
    global _total_alerts
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    with _lock:
        _total_alerts += 1
        entry = {
            "timestamp": ts,
            "attack_type": attack_type,
            "source_ip": source_ip,
            "description": description,
        }
        _recent_alerts.append(entry)
    if _db:
        try:
            _db.insert_alert(attack_type, source_ip, description, timestamp=ts)
        except Exception as e:
            logger.exception("Failed to save alert: %s", e)
    print(f"[ALERT] {ts} | {attack_type} | {source_ip} | {description}")


def _on_packet(delta: int) -> None:
    global _total_packets
    with _lock:
        _total_packets += delta


def _on_protocol(protocol: str) -> None:
    with _lock:
        if protocol in _protocol_counts:
            _protocol_counts[protocol] += 1
        else:
            _protocol_counts["Other"] += 1


def _get_stats() -> dict:
    with _lock:
        return {
            "total_packets": _total_packets,
            "total_alerts": _total_alerts,
            "protocol_distribution": dict(_protocol_counts),
            "sniffing_active": _sniffer.is_running() if _sniffer else False,
        }


def _get_recent_alerts() -> list:
    with _lock:
        return list(_recent_alerts)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    """Dashboard page."""
    return render_template("index.html")


@app.route("/logview")
def logs_page():
    """Logs page (all alerts from DB)."""
    return render_template("logs.html")


@app.route("/logs")
def api_logs():
    """Return all alerts from database (API)."""
    limit = request.args.get("limit", 500, type=int)
    limit = min(limit, 2000)
    alerts = _db.get_all_alerts(limit=limit)
    return jsonify({"alerts": alerts})


@app.route("/start", methods=["POST"])
def api_start():
    """Start packet sniffing in background."""
    global _sniffer
    if _sniffer is None:
        return jsonify({"ok": False, "message": "Sniffer not initialized"}), 500
    if _sniffer.is_running():
        return jsonify({"ok": True, "message": "Sniffing already active"})
    _sniffer.start()
    return jsonify({"ok": True, "message": "Sniffing started"})


@app.route("/stop", methods=["POST"])
def api_stop():
    """Stop packet sniffing."""
    global _sniffer
    if _sniffer:
        _sniffer.stop()
    return jsonify({"ok": True, "message": "Sniffing stopped"})


@app.route("/stats")
def api_stats():
    """Return current stats (packets, alerts, protocol dist, sniffing status)."""
    return jsonify(_get_stats())


@app.route("/alerts")
def api_alerts():
    """Return recent in-memory alerts for live feed."""
    return jsonify({"alerts": _get_recent_alerts()})


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    global _db, _engine, _sniffer
    _db = Database()
    _db.init_db()
    _engine = DetectionEngine(on_alert=_on_alert)
    _sniffer = PacketSniffer(
        detection_callback=_engine.process_packet,
        on_packet_count=_on_packet,
        on_protocol_count=_on_protocol,
    )
    logger.info("NIDS starting. Open http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()

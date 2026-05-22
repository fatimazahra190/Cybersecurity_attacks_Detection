"""
CyberSec Serving Layer — Flask REST API
Exposes threat data by merging HBase (batch) and Cassandra (speed).

Endpoints:
  GET /health              → system health
  GET /threats/ip/<ip>     → full IP profile (batch + speed)
  GET /threats/active      → all active alerts (last 24h)
  GET /threats/stats       → global batch statistics
  GET /threats/timeline    → hourly threat evolution
"""
import logging
import os
from datetime import datetime, timedelta, timezone

from flask import Flask, jsonify, request
from flask_cors import CORS

import hbase_service
import cassandra_service
import threat_fusion

# ── Logging ───────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger(__name__)

# ── App setup ─────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)   # Allow cross-origin requests from the dashboard

PORT = int(os.getenv("SERVER_PORT", "8080"))


# ── Health ────────────────────────────────────────────────────────────
@app.route("/health", methods=["GET"])
def health():
    """
    Returns 200 if all components are UP, 503 if degraded.
    SLA: < 50 ms
    """
    hbase_ok     = False
    cassandra_ok = False

    try:
        hbase_ok = hbase_service.is_healthy()
    except Exception as e:
        logger.warning("HBase health check exception: %s", e)

    try:
        cassandra_ok = cassandra_service.is_healthy()
    except Exception as e:
        logger.warning("Cassandra health check exception: %s", e)

    components = {
        "api":       "UP",
        "hbase":     "UP" if hbase_ok     else "DOWN",
        "cassandra": "UP" if cassandra_ok else "DOWN",
    }
    all_healthy = hbase_ok and cassandra_ok
    payload = {
        "status":     "UP" if all_healthy else "DEGRADED",
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "components": components,
    }
    return jsonify(payload), (200 if all_healthy else 503)


# ── Threat profile ────────────────────────────────────────────────────
@app.route("/threats/ip/<ip>", methods=["GET"])
def get_threat_profile(ip: str):
    """
    Full threat profile for an IP: batch reputation + speed alerts.
    SLA: < 200 ms (p95)
    """
    logger.info("GET /threats/ip/%s", ip)

    # Basic input validation
    ip = ip.strip()
    if not ip or len(ip) > 45:
        return jsonify({"error": "Invalid IP address"}), 400

    profile = threat_fusion.get_threat_profile(ip)
    return jsonify(profile), 200


# ── Active alerts ─────────────────────────────────────────────────────
@app.route("/threats/active", methods=["GET"])
def get_active_alerts():
    """
    All active alerts from the last 24 h (Cassandra TTL).
    SLA: < 300 ms
    """
    logger.info("GET /threats/active")
    alerts = cassandra_service.get_all_active_alerts(limit=200)
    return jsonify(alerts), 200


# ── Global stats ──────────────────────────────────────────────────────
@app.route("/threats/stats", methods=["GET"])
def get_stats():
    """
    Global batch statistics (HBase scan).
    SLA: < 500 ms
    """
    logger.info("GET /threats/stats")
    stats = hbase_service.get_global_stats()
    return jsonify(stats), 200


# ── Timeline ──────────────────────────────────────────────────────────
@app.route("/threats/timeline", methods=["GET"])
def get_timeline():
    """
    Hourly threat counts in a date range.
    Query params: from=yyyyMMdd, to=yyyyMMdd
    SLA: < 500 ms
    """
    logger.info("GET /threats/timeline")
    today     = datetime.utcnow().strftime("%Y%m%d")
    yesterday = (datetime.utcnow() - timedelta(days=1)).strftime("%Y%m%d")

    from_date = request.args.get("from", "20240101")
    to_date   = request.args.get("to",   "20241231")

    timeline = hbase_service.get_timeline(from_date, to_date)
    return jsonify(timeline), 200


# ── Error handlers ────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(500)
def internal_error(e):
    logger.error("Internal error: %s", e)
    return jsonify({"error": "Internal server error"}), 500


# ── Startup ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    logger.info("╔══════════════════════════════════════════════╗")
    logger.info("║   CyberSec Serving Layer — Starting          ║")
    logger.info("║   Port: %-5d                                ║", PORT)
    logger.info("╚══════════════════════════════════════════════╝")

    # Ensure Cassandra schema exists before accepting requests
    try:
        cassandra_service.ensure_schema()
    except Exception as e:
        logger.warning("Schema init warning (non-fatal): %s", e)

    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)

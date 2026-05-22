"""
Threat Fusion Service — combines batch (HBase) and speed (Cassandra) layers
to produce a unified threat profile per IP with a recommendation.

Recommendation logic (PRD §5.1.3):
  batch_score > 80 AND active_alerts >= 1  →  BLOCK
  batch_score >= 50                         →  MONITOR
  active_alerts > 0                         →  MONITOR
  otherwise                                 →  ALLOW

Confidence = (batch_score * 0.4 + speed_score * 0.6) / 100, capped at 1.0
"""
import logging
from typing import Dict, Any

import hbase_service
import cassandra_service

logger = logging.getLogger(__name__)


def compute_recommendation(batch_score: int, active_alerts: int) -> str:
    if batch_score > 80 and active_alerts >= 1:
        return "BLOCK"
    if batch_score >= 50:
        return "MONITOR"
    if active_alerts > 0:
        return "MONITOR"
    return "ALLOW"


def compute_confidence(batch_score: int, speed_score: int) -> float:
    weighted = batch_score * 0.4 + speed_score * 0.6
    return round(min(1.0, weighted / 100.0), 2)


def get_threat_profile(ip: str) -> Dict[str, Any]:
    """Build and return the full threat profile for an IP address."""
    logger.info("Building threat profile for IP: %s", ip)

    # ── Batch layer (HBase) ──────────────────────────────────────────
    batch_data   = hbase_service.get_ip_reputation(ip)
    attack_types = hbase_service.get_attack_types(ip)

    # ── Speed layer (Cassandra) ──────────────────────────────────────
    active_alerts      = cassandra_service.get_active_alerts(ip)
    current_score      = cassandra_service.get_current_threat_score(ip)
    bytes_total        = cassandra_service.get_bytes_total(ip)
    recent_attack_types = cassandra_service.get_recent_attack_types(ip)

    last_seen = None
    if active_alerts:
        last_seen = active_alerts[0].get("lastSeen")

    batch_score = int(batch_data.get("reputation_score", 0))
    recommendation = compute_recommendation(batch_score, len(active_alerts))
    confidence     = compute_confidence(batch_score, current_score)

    profile = {
        "ip": ip,
        "batchLayer": {
            "reputationScore":        batch_score,
            "totalHistoricalEvents":  batch_data.get("total_historical_events", 0),
            "attackTypesDetected":    attack_types,
            "firstSeen":              batch_data.get("first_seen"),
            "lastBatchUpdate":        batch_data.get("last_batch_update"),
        },
        "speedLayer": {
            "activeAlerts":       len(active_alerts),
            "lastSeen":           last_seen,
            "currentThreatScore": current_score,
            "recentAttackTypes":  recent_attack_types,
            "bytesLastHour":      bytes_total,
        },
        "recommendation": recommendation,
        "confidence":      confidence,
    }

    logger.info(
        "Profile %s → batch=%d | alerts=%d | rec=%s | conf=%.2f",
        ip, batch_score, len(active_alerts), recommendation, confidence,
    )
    return profile

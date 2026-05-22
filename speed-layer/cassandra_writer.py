"""
Cassandra writer utility for speed layer detectors.
Writes real-time alerts to cybersecurity.active_threats (TTL 24h).
"""
import os
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from cassandra.cluster import Cluster
from cassandra.policies import RoundRobinPolicy, RetryPolicy
from cassandra.auth import PlainTextAuthProvider

logger = logging.getLogger(__name__)

CASSANDRA_HOST = os.getenv("CASSANDRA_HOST", "cassandra")
CASSANDRA_PORT = int(os.getenv("CASSANDRA_PORT", "9042"))
KEYSPACE = "cybersecurity"

INSERT_CQL = """
INSERT INTO cybersecurity.active_threats
  (ip_source, bucket_time, alert_id, last_seen, threat_score,
   attack_types, alert_type, severity, event_count, bytes_total,
   user_agents, log_sources)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
USING TTL 86400
"""

_session = None
_prepared = None


def _get_session():
    global _session, _prepared
    if _session is None or _session.is_shutdown:
        cluster = Cluster(
            [CASSANDRA_HOST],
            port=CASSANDRA_PORT,
            load_balancing_policy=RoundRobinPolicy(),
            default_retry_policy=RetryPolicy(),
            connect_timeout=30,
            control_connection_timeout=30,
        )
        _session = cluster.connect(KEYSPACE)
        _prepared = _session.prepare(INSERT_CQL)
        logger.info("Cassandra session established: %s:%d", CASSANDRA_HOST, CASSANDRA_PORT)
    return _session, _prepared


def write_alert(
    ip_source: str,
    alert_type: str,
    severity: str,
    threat_score: int,
    event_count: int,
    bytes_total: int,
    user_agent: Optional[str] = None,
    log_source: Optional[str] = None,
) -> None:
    """Write a single alert row to Cassandra."""
    try:
        session, prepared = _get_session()
        now = datetime.now(timezone.utc)

        session.execute(prepared, (
            ip_source,
            now,
            uuid.uuid4(),
            now,
            threat_score,
            {alert_type},
            alert_type,
            severity,
            event_count,
            bytes_total,
            {user_agent or "unknown"},
            {log_source or "unknown"},
        ))
        logger.debug("Alert written: %s | %s | score=%d", ip_source, alert_type, threat_score)
    except Exception as e:
        logger.error("Cassandra write error for IP %s: %s", ip_source, e)


def write_alerts_batch(alerts: list) -> None:
    """Write multiple alerts from a list of dicts (used in Spark foreachBatch)."""
    for alert in alerts:
        try:
            write_alert(
                ip_source=alert.get("source_ip") or alert.get("ip_source", "unknown"),
                alert_type=alert.get("alert_type", "UNKNOWN"),
                severity=alert.get("severity", "MEDIUM"),
                threat_score=int(alert.get("threat_score", 50)),
                event_count=int(alert.get("event_count", 1)),
                bytes_total=int(alert.get("bytes_total") or alert.get("bytes_transferred", 0)),
                user_agent=alert.get("user_agent", "unknown"),
                log_source=alert.get("log_type", "unknown"),
            )
        except Exception as e:
            logger.error("batch write error: %s — %s", alert, e)

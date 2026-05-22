"""
Cassandra service for the serving layer.
Reads real-time alerts from cybersecurity.active_threats.
"""
import os
import logging
from typing import List, Dict, Any, Optional

from cassandra.cluster import Cluster
from cassandra.policies import RoundRobinPolicy

logger = logging.getLogger(__name__)

CASSANDRA_HOST = os.getenv("CASSANDRA_HOST", "cassandra")
CASSANDRA_PORT = int(os.getenv("CASSANDRA_PORT", "9042"))
CASSANDRA_DC   = os.getenv("CASSANDRA_DC", "datacenter1")
KEYSPACE = "cybersecurity"

_session = None


def _get_session():
    global _session
    if _session is None or _session.is_shutdown:
        cluster = Cluster(
            [CASSANDRA_HOST],
            port=CASSANDRA_PORT,
            load_balancing_policy=RoundRobinPolicy(),
            connect_timeout=30,
            control_connection_timeout=30,
        )
        _session = cluster.connect(KEYSPACE)
        logger.info("Cassandra session ready: %s:%d", CASSANDRA_HOST, CASSANDRA_PORT)
    return _session


def _row_to_dict(row) -> Dict[str, Any]:
    """Convert a Cassandra Row to a plain dict for JSON serialization."""
    return {
        "ipSource":    row.ip_source,
        "bucketTime":  row.bucket_time.isoformat() if row.bucket_time else None,
        "alertId":     str(row.alert_id) if row.alert_id else None,
        "lastSeen":    row.last_seen.isoformat() if row.last_seen else None,
        "threatScore": row.threat_score or 0,
        "attackTypes": list(row.attack_types) if row.attack_types else [],
        "alertType":   row.alert_type,
        "severity":    row.severity,
        "eventCount":  row.event_count or 0,
        "bytesTotal":  row.bytes_total or 0,
        "userAgents":  list(row.user_agents) if row.user_agents else [],
        "logSources":  list(row.log_sources) if row.log_sources else [],
    }


def get_active_alerts(ip: str) -> List[Dict[str, Any]]:
    """Return the 10 most recent active alerts for a given IP."""
    try:
        session = _get_session()
        rows = session.execute(
            "SELECT * FROM active_threats WHERE ip_source = %s LIMIT 10",
            (ip,)
        )
        return [_row_to_dict(r) for r in rows]
    except Exception as e:
        logger.error("Cassandra get_active_alerts error for %s: %s", ip, e)
        return []


def get_all_active_alerts(limit: int = 200) -> List[Dict[str, Any]]:
    """Return all active alerts (last 24h), sorted by threat score desc."""
    try:
        session = _get_session()
        # ALLOW FILTERING needed without secondary index
        rows = session.execute(
            f"SELECT * FROM active_threats LIMIT {limit} ALLOW FILTERING"
        )
        alerts = [_row_to_dict(r) for r in rows]
        alerts.sort(key=lambda a: a["threatScore"], reverse=True)
        return alerts
    except Exception as e:
        logger.error("Cassandra get_all_active_alerts error: %s", e)
        return []


def get_current_threat_score(ip: str) -> int:
    """Return the maximum threat score across active alerts for this IP."""
    alerts = get_active_alerts(ip)
    if not alerts:
        return 0
    return max(a["threatScore"] for a in alerts)


def get_bytes_total(ip: str) -> int:
    """Sum bytes_total from active alerts for this IP."""
    return sum(a["bytesTotal"] for a in get_active_alerts(ip))


def get_recent_attack_types(ip: str) -> List[str]:
    """Collect unique recent attack types for this IP."""
    seen = set()
    for alert in get_active_alerts(ip):
        seen.update(alert.get("attackTypes", []))
        if alert.get("alertType"):
            seen.add(alert["alertType"])
    return list(seen)


def is_healthy() -> bool:
    """Health check: simple CQL ping."""
    try:
        _get_session().execute("SELECT now() FROM system.local")
        return True
    except Exception as e:
        logger.warning("Cassandra health check failed: %s", e)
        return False


def ensure_schema() -> None:
    """Create keyspace + table if they don't exist. Safe to call repeatedly."""
    cluster = Cluster(
        [CASSANDRA_HOST],
        port=CASSANDRA_PORT,
        load_balancing_policy=RoundRobinPolicy(),
        connect_timeout=60,
    )
    try:
        session = cluster.connect()
        session.execute(f"""
            CREATE KEYSPACE IF NOT EXISTS {KEYSPACE}
            WITH replication = {{'class': 'SimpleStrategy', 'replication_factor': 1}}
        """)
        session.set_keyspace(KEYSPACE)
        session.execute("""
            CREATE TABLE IF NOT EXISTS active_threats (
                ip_source    TEXT,
                bucket_time  TIMESTAMP,
                alert_id     UUID,
                last_seen    TIMESTAMP,
                threat_score INT,
                attack_types SET<TEXT>,
                alert_type   TEXT,
                severity     TEXT,
                event_count  INT,
                bytes_total  BIGINT,
                user_agents  SET<TEXT>,
                log_sources  SET<TEXT>,
                PRIMARY KEY ((ip_source), bucket_time, alert_id)
            ) WITH default_time_to_live = 86400
              AND CLUSTERING ORDER BY (bucket_time DESC)
        """)
        logger.info("Cassandra schema ready.")
    except Exception as e:
        logger.error("Cassandra ensure_schema error: %s", e)
    finally:
        cluster.shutdown()

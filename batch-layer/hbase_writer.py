
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

HBASE_HOST = os.getenv("HBASE_HOST", "hbase")
HBASE_PORT = int(os.getenv("HBASE_PORT", "9090"))


def _get_connection():
    import happybase
    return happybase.Connection(
        host=HBASE_HOST,
        port=HBASE_PORT,
        timeout=60000,        # 60s — was 10s, too short for large batches
        autoconnect=True,
        transport="buffered",
        protocol="binary",
    )


def write_ip_reputation(rows: list) -> None:
    if not rows:
        return
    logger.info("Writing %d IP reputations to HBase...", len(rows))
    try:
        conn = _get_connection()
        table = conn.table("ip_reputation")
        now = datetime.utcnow().isoformat()
        # Write one by one to avoid batch timeout on slow connections
        for row in rows:
            ip = str(row.get("source_ip", "unknown"))
            data = {
                b"stats:score":          str(row.get("reputation_score", 0)).encode(),
                b"stats:total_events":   str(row.get("total_events", 0)).encode(),
                b"stats:unique_targets": str(row.get("unique_targets", 0)).encode(),
                b"stats:total_bytes":    str(row.get("total_bytes", 0)).encode(),
                b"meta:last_seen":       now.encode(),
                b"meta:log_types":       str(row.get("log_type", "")).encode(),
            }
            table.put(ip.encode(), data)
        conn.close()
        logger.info("Wrote %d rows to ip_reputation.", len(rows))
    except Exception as e:
        logger.error("HBase write_ip_reputation error: %s", e)
        logger.warning("Continuing without HBase write — HDFS data is still saved.")


def write_attack_pattern(rows: list, attack_type: str) -> None:
    if not rows:
        return
    logger.info("Writing %d %s patterns to HBase...", len(rows), attack_type)
    # Limit to top 200 rows to avoid OOM and timeout
    rows = rows[:200]
    try:
        conn = _get_connection()
        table = conn.table("attack_patterns")
        now = datetime.utcnow().isoformat()
        for row in rows:
            ip = str(row.get("source_ip", "unknown"))
            row_key = f"{attack_type}|{ip}".encode()
            data = {
                b"pattern:category":  attack_type.encode(),
                b"pattern:source_ip": ip.encode(),
                b"freq:count":        str(row.get("distinct_targets", row.get("event_count", 0))).encode(),
                b"freq:last_seen":    now.encode(),
            }
            table.put(row_key, data)
        conn.close()
        logger.info("Wrote %d rows to attack_patterns.", len(rows))
    except Exception as e:
        logger.error("HBase write_attack_pattern error: %s", e)
        logger.warning("Continuing without HBase write — HDFS data is still saved.")


def write_threat_timeline(rows: list) -> None:
    if not rows:
        return
    logger.info("Writing %d timeline entries to HBase...", len(rows))
    try:
        conn = _get_connection()
        table = conn.table("threat_timeline")
        for row in rows:
            date_str = str(row.get("event_date", ""))
            hour_str = str(row.get("event_hour", "0")).zfill(2)
            row_key = f"{date_str}|{hour_str}".encode()
            data = {
                b"counts:malicious":  str(row.get("malicious_count", 0)).encode(),
                b"counts:suspicious": str(row.get("suspicious_count", 0)).encode(),
                b"counts:benign":     str(row.get("benign_count", 0)).encode(),
            }
            table.put(row_key, data)
        conn.close()
        logger.info("Wrote %d timeline rows.", len(rows))
    except Exception as e:
        logger.error("HBase write_threat_timeline error: %s", e)
        logger.warning("Continuing without HBase write — HDFS data is still saved.")


def ensure_tables_exist() -> None:
    tables = {
        "ip_reputation":   [b"stats", b"meta"],
        "attack_patterns": [b"pattern", b"freq"],
        "threat_timeline": [b"counts", b"breakdown"],
    }
    try:
        conn = _get_connection()
        existing = [t.decode() for t in conn.tables()]
        for name, families in tables.items():
            if name not in existing:
                conn.create_table(name, {f.decode(): {} for f in families})
                logger.info("Created HBase table: %s", name)
        conn.close()
    except Exception as e:
        logger.warning("HBase ensure_tables_exist warning: %s", e)

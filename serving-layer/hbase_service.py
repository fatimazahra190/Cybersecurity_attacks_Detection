"""
HBase service for the serving layer.
Reads batch data from HBase tables.
"""
import os
import logging
from typing import List, Dict, Any, Optional

import happybase

logger = logging.getLogger(__name__)

HBASE_HOST     = os.getenv("HBASE_HOST", "hbase")
HBASE_PORT     = int(os.getenv("HBASE_PORT", "9090"))
ZOOKEEPER_HOST = os.getenv("ZOOKEEPER_HOST", "zookeeper")

_connection: Optional[happybase.Connection] = None


def _get_conn() -> happybase.Connection:
    global _connection
    try:
        if _connection is None or not _connection.transport.isOpen():
            _connection = happybase.Connection(
                host=HBASE_HOST,
                port=HBASE_PORT,
                timeout=10000,
                autoconnect=True,
            )
    except Exception:
        _connection = happybase.Connection(
            host=HBASE_HOST,
            port=HBASE_PORT,
            timeout=10000,
            autoconnect=True,
        )
    return _connection


def get_ip_reputation(ip: str) -> Dict[str, Any]:
    """
    Read IP historical reputation from HBase ip_reputation table.
    Returns zero-value dict if IP is not found.
    """
    result = {
        "ip": ip,
        "reputation_score": 0,
        "total_historical_events": 0,
        "unique_targets": 0,
        "total_bytes": 0,
        "first_seen": None,
        "last_batch_update": None,
        "log_types": None,
    }
    try:
        conn = _get_conn()
        table = conn.table("ip_reputation")
        row = table.row(ip.encode())
        if not row:
            return result

        def _get(family_col: bytes) -> Optional[str]:
            val = row.get(family_col)
            return val.decode() if val else None

        result["reputation_score"]         = int(_get(b"stats:score") or 0)
        result["total_historical_events"]  = int(_get(b"stats:total_events") or 0)
        result["unique_targets"]           = int(_get(b"stats:unique_targets") or 0)
        result["total_bytes"]              = int(_get(b"stats:total_bytes") or 0)
        result["last_batch_update"]        = _get(b"meta:last_seen")
        result["log_types"]                = _get(b"meta:log_types")
    except Exception as e:
        logger.error("HBase get_ip_reputation error for %s: %s", ip, e)
    return result


def get_attack_types(ip: str) -> List[str]:
    """Return list of attack types detected in batch for this IP."""
    types = []
    known = ["PORT_SCAN", "SQLI", "XSS", "LFI", "TOOL_DETECTED", "BRUTE_FORCE", "INJECTION"]
    try:
        conn = _get_conn()
        table = conn.table("attack_patterns")
        for attack_type in known:
            row_key = f"{attack_type}|{ip}".encode()
            row = table.row(row_key)
            if row:
                types.append(attack_type)
    except Exception as e:
        logger.error("HBase get_attack_types error for %s: %s", ip, e)
    return types


def get_timeline(from_date: str, to_date: str) -> List[Dict[str, Any]]:
    """Scan threat_timeline table for hourly counts in a date range."""
    timeline = []
    try:
        conn = _get_conn()
        table = conn.table("threat_timeline")
        start_row = f"{from_date}|00".encode()
        stop_row  = f"{to_date}|24".encode()

        for key, data in table.scan(row_start=start_row, row_stop=stop_row):
            parts = key.decode().split("|")
            if len(parts) < 2:
                continue
            entry = {
                "date": parts[0],
                "hour": parts[1],
                "malicious":  int(data.get(b"counts:malicious",  b"0").decode()),
                "suspicious": int(data.get(b"counts:suspicious", b"0").decode()),
                "benign":     int(data.get(b"counts:benign",     b"0").decode()),
            }
            timeline.append(entry)
    except Exception as e:
        logger.error("HBase get_timeline error: %s", e)
    return timeline


def get_global_stats() -> Dict[str, Any]:
    """Aggregate statistics from HBase for /threats/stats endpoint."""
    stats = {
        "source": "batch_layer",
        "total_ips_analyzed": 0,
        "high_risk_ips": 0,
        "note": "Results from last Spark batch jobs",
    }
    try:
        conn = _get_conn()
        table = conn.table("ip_reputation")
        total = 0
        high_risk = 0
        for _key, data in table.scan(columns=[b"stats:score"]):
            total += 1
            score = int(data.get(b"stats:score", b"0").decode())
            if score > 70:
                high_risk += 1
        stats["total_ips_analyzed"] = total
        stats["high_risk_ips"] = high_risk
    except Exception as e:
        logger.error("HBase get_global_stats error: %s", e)
        stats["error"] = "HBase temporarily unavailable"
    return stats


def is_healthy() -> bool:
    """Health check: verify Thrift connection only."""
    try:
        conn = _get_conn()
        conn.tables()  # just lists tables, never throws TableNotFoundException
        return True
    except Exception as e:
        logger.warning("HBase health check failed: %s", e)
        return False

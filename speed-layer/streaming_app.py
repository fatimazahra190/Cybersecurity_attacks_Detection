"""
Speed Layer — Spark Structured Streaming Application
Runs 3 detectors concurrently on the Kafka 'cybersecurity-logs' topic:
  1. BruteForceDetector    : 5+ blocked in 1 minute
  2. SignatureDetector     : sqlmap/nikto/SQLi/XSS/LFI patterns
  3. VolumeAnomalyDetector : >10 MB in 10 seconds

Each detector writes alerts to Cassandra (TTL 24h).
"""
import os
import sys
import logging

# Ensure speed-layer directory is on the path so cassandra_writer is importable
# both when running locally and inside the Docker container
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import (
    StructType, StructField,
    StringType, LongType, TimestampType
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s - %(message)s")
logger = logging.getLogger(__name__)

KAFKA_BOOTSTRAP  = os.getenv("KAFKA_BOOTSTRAP", "kafka:29092")
CASSANDRA_HOST   = os.getenv("CASSANDRA_HOST", "cassandra")
CASSANDRA_PORT   = int(os.getenv("CASSANDRA_PORT", "9042"))
TOPIC = "cybersecurity-logs"
CHECKPOINT_BASE = "/tmp/checkpoints"

# ── Patterns ──────────────────────────────────────────────────────────
TOOL_PATTERN = r"(?i)(sqlmap|nikto|nmap|masscan|burpsuite|dirbuster|hydra|metasploit|w3af|acunetix|openvas)"
SQLI_PATTERN = r"(?i)('\s+OR|UNION\s+SELECT|1=1--|DROP\s+TABLE|xp_cmdshell|EXEC\()"
XSS_PATTERN  = r"(?i)(<script|javascript:|onerror=|alert\(|document\.cookie|eval\()"
LFI_PATTERN  = r"(?i)(\.\.\/\.\.\.|/etc/passwd|/etc/shadow|%2e%2e%2f)"

# ── Kafka message schema ──────────────────────────────────────────────
MESSAGE_SCHEMA = StructType([
    StructField("timestamp",         TimestampType(), True),
    StructField("source_ip",         StringType(),    True),
    StructField("dest_ip",           StringType(),    True),
    StructField("protocol",          StringType(),    True),
    StructField("action",            StringType(),    True),
    StructField("threat_label",      StringType(),    True),
    StructField("log_type",          StringType(),    True),
    StructField("bytes_transferred", LongType(),      True),
    StructField("user_agent",        StringType(),    True),
    StructField("request_path",      StringType(),    True),
])


def create_spark_session() -> SparkSession:
    spark = (
        SparkSession.builder
        .appName("CyberSecStreamingApp")
        .master("local[*]")
        .config("spark.sql.shuffle.partitions", "4")
        .config("spark.streaming.stopGracefullyOnShutdown", "true")
        .config("spark.sql.legacy.timeParserPolicy", "LEGACY")
        .config("spark.ui.enabled", "false")
        # Kafka packages — already in jars dir
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("WARN")
    return spark


def create_kafka_stream(spark: SparkSession):
    """Create parsed Kafka stream as structured DataFrame."""
    raw = (
        spark.readStream
        .format("kafka")
        .option("kafka.bootstrap.servers", KAFKA_BOOTSTRAP)
        .option("subscribe", TOPIC)
        .option("startingOffsets", "latest")
        .option("failOnDataLoss", "false")
        .option("maxOffsetsPerTrigger", "10000")
        .load()
    )
    return (
        raw
        .selectExpr("CAST(value AS STRING) as json_value")
        .select(F.from_json(F.col("json_value"), MESSAGE_SCHEMA).alias("data"))
        .select("data.*")
        .filter(F.col("source_ip").isNotNull())
    )


def _cassandra_batch_writer(df, batch_id: int, alert_type_label: str):
    """Write a micro-batch DataFrame to Cassandra."""
    rows = df.collect()
    if not rows:
        return

    logger.warning("Batch %d — %d %s alerts", batch_id, len(rows), alert_type_label)

    # Import here so Spark serializes the Python env
    import cassandra_writer as cw
    alerts = [r.asDict() for r in rows]
    cw.write_alerts_batch(alerts)


def start_brute_force_detector(stream):
    """Detect: 5+ blocked connections from same source_ip in 1 minute."""
    THRESHOLD = 5

    alerts = (
        stream
        .filter(F.col("action") == "blocked")
        .groupBy(
            F.window(F.col("timestamp"), "1 minute"),
            F.col("source_ip"),
        )
        .agg(
            F.count("*").alias("blocked_count"),
            F.first("user_agent").alias("user_agent"),
            F.first("log_type").alias("log_type"),
            F.sum("bytes_transferred").alias("bytes_total"),
        )
        .filter(F.col("blocked_count") > THRESHOLD)
        .withColumn("alert_type", F.lit("BRUTE_FORCE"))
        .withColumn(
            "threat_score",
            F.least(F.lit(100),
                    (F.lit(70) + (F.col("blocked_count") - THRESHOLD) * 2).cast("int")),
        )
        .withColumn(
            "severity",
            F.when(F.col("blocked_count") > 10, "CRITICAL").otherwise("HIGH"),
        )
        .withColumn("event_count", F.col("blocked_count").cast("int"))
        .fillna(0, ["bytes_total"])
    )

    return (
        alerts.writeStream
        .outputMode("update")
        .option("checkpointLocation", f"{CHECKPOINT_BASE}/bruteforce")
        .trigger(processingTime="500 milliseconds")
        .foreachBatch(lambda df, bid: _cassandra_batch_writer(df, bid, "BRUTE_FORCE"))
        .start()
    )


def start_signature_detector(stream):
    """Detect known attack tools and injection patterns."""
    tool_col = F.col("user_agent").rlike(TOOL_PATTERN)
    sqli_col = F.col("request_path").rlike(SQLI_PATTERN)
    xss_col  = F.col("request_path").rlike(XSS_PATTERN)
    lfi_col  = F.col("request_path").rlike(LFI_PATTERN)

    alerts = (
        stream
        .filter(tool_col | sqli_col | xss_col | lfi_col)
        .withColumn(
            "alert_type",
            F.when(tool_col, "KNOWN_ATTACK_TOOL")
            .when(sqli_col, "SQLI_DETECTED")
            .when(xss_col,  "XSS_DETECTED")
            .when(lfi_col,  "LFI_DETECTED")
            .otherwise("SIGNATURE_MATCH"),
        )
        .withColumn(
            "threat_score",
            F.when(tool_col, 95).when(sqli_col, 85).when(xss_col, 75).when(lfi_col, 70).otherwise(60),
        )
        .withColumn("severity", F.lit("CRITICAL"))
        .withColumn("event_count", F.lit(1))
        .withColumn("bytes_total", F.col("bytes_transferred").cast("long"))
        .fillna(0, ["bytes_total"])
    )

    return (
        alerts.writeStream
        .outputMode("append")
        .option("checkpointLocation", f"{CHECKPOINT_BASE}/signatures")
        .trigger(processingTime="500 milliseconds")
        .foreachBatch(lambda df, bid: _cassandra_batch_writer(df, bid, "SIGNATURE"))
        .start()
    )


def start_volume_anomaly_detector(stream):
    """Detect: sum(bytes) > 10 MB from same source_ip in 10 seconds."""
    THRESHOLD_BYTES = 10 * 1024 * 1024    # 10 MB
    CRITICAL_BYTES  = 100 * 1024 * 1024   # 100 MB

    alerts = (
        stream
        .groupBy(
            F.window(F.col("timestamp"), "10 seconds"),
            F.col("source_ip"),
        )
        .agg(
            F.sum("bytes_transferred").alias("bytes_total"),
            F.count("*").alias("event_count"),
            F.first("log_type").alias("log_type"),
            F.first("user_agent").alias("user_agent"),
        )
        .filter(F.col("bytes_total") > THRESHOLD_BYTES)
        .withColumn("alert_type", F.lit("VOLUME_ANOMALY"))
        .withColumn(
            "threat_score",
            F.least(
                F.lit(100),
                (F.lit(80) + F.log(10.0, F.col("bytes_total") / F.lit(1048576.0)) * 5).cast("int"),
            ),
        )
        .withColumn(
            "severity",
            F.when(F.col("bytes_total") > CRITICAL_BYTES, "CRITICAL").otherwise("HIGH"),
        )
        .fillna(0, ["bytes_total"])
    )

    return (
        alerts.writeStream
        .outputMode("update")
        .option("checkpointLocation", f"{CHECKPOINT_BASE}/volume")
        .trigger(processingTime="500 milliseconds")
        .foreachBatch(lambda df, bid: _cassandra_batch_writer(df, bid, "VOLUME_ANOMALY"))
        .start()
    )


def main():
    logger.info("═" * 50)
    logger.info("  CyberSec Speed Layer — Starting")
    logger.info("  Kafka: %s  |  Cassandra: %s:%d", KAFKA_BOOTSTRAP, CASSANDRA_HOST, CASSANDRA_PORT)
    logger.info("═" * 50)

    spark = create_spark_session()

    try:
        stream = create_kafka_stream(spark)

        q1 = start_brute_force_detector(stream)
        q2 = start_signature_detector(stream)
        q3 = start_volume_anomaly_detector(stream)

        logger.info("✅ 3 detectors active. Waiting for Kafka messages on topic '%s'…", TOPIC)
        logger.info("   Q1 BruteForce: %s", q1.name)
        logger.info("   Q2 Signature : %s", q2.name)
        logger.info("   Q3 Volume    : %s", q3.name)

        spark.streams.awaitAnyTermination()
    except Exception as e:
        logger.error("Streaming app error: %s", e, exc_info=True)
        sys.exit(1)
    finally:
        spark.stop()


if __name__ == "__main__":
    main()


import logging
from pyspark.sql import SparkSession, DataFrame
from pyspark.sql import functions as F

from spark_config import create_session, hdfs_path
import hbase_writer

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s - %(message)s")
logger = logging.getLogger(__name__)


def analyze_volume(logs: DataFrame) -> DataFrame:
    """Correlate bytes_transferred with threat_label."""
    return (
        logs.groupBy("threat_label", "log_type", "protocol")
        .agg(
            F.avg("bytes_transferred").alias("avg_bytes"),
            F.max("bytes_transferred").alias("max_bytes"),
            F.percentile_approx("bytes_transferred", 0.95).alias("p95_bytes"),
            F.count("*").alias("event_count"),
            F.sum("bytes_transferred").alias("total_bytes"),
        )
        .orderBy(F.col("total_bytes").desc())
    )


def build_timeline(logs: DataFrame) -> DataFrame:
    """Build hourly threat counts for timeline chart."""
    with_date = (
        logs
        .withColumn("event_date", F.date_format(F.col("timestamp"), "yyyyMMdd"))
        .withColumn("event_hour", F.hour(F.col("timestamp")))
    )

    mal = (
        with_date.filter(F.col("threat_label") == "malicious")
        .groupBy("event_date", "event_hour")
        .agg(F.count("*").alias("malicious_count"))
    )
    sus = (
        with_date.filter(F.col("threat_label") == "suspicious")
        .groupBy("event_date", "event_hour")
        .agg(F.count("*").alias("suspicious_count"))
    )
    ben = (
        with_date.filter(F.col("threat_label") == "benign")
        .groupBy("event_date", "event_hour")
        .agg(F.count("*").alias("benign_count"))
    )

    join_cols = ["event_date", "event_hour"]
    timeline = (
        mal.join(sus, join_cols, "full")
        .join(ben, join_cols, "full")
        .fillna(0, ["malicious_count", "suspicious_count", "benign_count"])
        .orderBy("event_date", "event_hour")
    )
    return timeline


def run():
    logger.info("=== Starting Job: Volume Analysis ===")
    spark = create_session("VolumeAnalysis")
    spark.sparkContext.setLogLevel("WARN")

    try:
        logs = spark.read.parquet(hdfs_path("/data/cybersecurity/logs"))

        # Volume analysis
        vol_result = analyze_volume(logs)
        vol_result.show(20, truncate=False)
        vol_result.write.mode("overwrite").parquet(hdfs_path("/data/cybersecurity/batch/volume_analysis"))
        logger.info("Volume analysis saved.")

        # Timeline
        timeline = build_timeline(logs)
        timeline.show(24, truncate=False)
        rows = [row.asDict() for row in timeline.collect()]
        hbase_writer.write_threat_timeline(rows)
        logger.info("Timeline written to HBase.")

        logger.info("=== Job VolumeAnalysis completed ===")
    except Exception as e:
        logger.error("Job failed: %s", e, exc_info=True)
        raise
    finally:
        spark.stop()


if __name__ == "__main__":
    run()

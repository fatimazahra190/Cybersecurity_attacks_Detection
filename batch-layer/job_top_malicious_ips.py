
import logging
from pyspark.sql import SparkSession, DataFrame
from pyspark.sql import functions as F

from spark_config import create_session, hdfs_path
import hbase_writer

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s - %(message)s")
logger = logging.getLogger(__name__)


def analyze(spark: SparkSession) -> DataFrame:
    """Core analysis logic - testable without side effects."""
    input_path = hdfs_path("/data/cybersecurity/logs")
    logger.info("Reading logs from %s", input_path)

    logs = spark.read.parquet(input_path)
    logger.info("Total log count: %d", logs.count())

    # Count malicious events per IP
    malicious_counts = (
        logs.filter(F.col("threat_label") == "malicious")
        .groupBy("source_ip")
        .agg(F.count("*").alias("malicious_count"))
    )

    # Count suspicious events per IP
    suspicious_counts = (
        logs.filter(F.col("threat_label") == "suspicious")
        .groupBy("source_ip")
        .agg(F.count("*").alias("suspicious_count"))
    )

    # Aggregate suspicious + malicious events
    suspicious_or_mal = (
        logs.filter(F.col("threat_label").isin("suspicious", "malicious"))
        .groupBy("source_ip", "log_type")
        .agg(
            F.count("*").alias("total_events"),
            F.countDistinct("dest_ip").alias("unique_targets"),
            F.sum("bytes_transferred").alias("total_bytes"),
        )
    )

    # Join all together
    result = (
        suspicious_or_mal
        .join(malicious_counts, "source_ip", "left")
        .join(suspicious_counts, "source_ip", "left")
        .fillna(0, ["malicious_count", "suspicious_count"])
        .withColumn(
            "reputation_score",
            F.least(
                F.lit(100),
                (
                    (F.col("malicious_count") * 10 + F.col("suspicious_count") * 5)
                    / F.col("total_events")
                    * 100
                ).cast("long"),
            ),
        )
        .orderBy(F.col("total_events").desc())
        .limit(10)
    )
    return result


def run():
    logger.info("=== Starting Job: Top Malicious IPs ===")
    spark = create_session("TopMaliciousIPs")
    spark.sparkContext.setLogLevel("WARN")

    try:
        result = analyze(spark)
        result.show(10, truncate=False)

        # Save to HDFS
        out_path = hdfs_path("/data/cybersecurity/batch/ip_reputation")
        result.write.mode("overwrite").parquet(out_path)
        logger.info("Saved to HDFS: %s", out_path)

        # Write to HBase
        rows = [row.asDict() for row in result.collect()]
        hbase_writer.write_ip_reputation(rows)

        logger.info("=== Job TopMaliciousIPs completed ===")
    except Exception as e:
        logger.error("Job failed: %s", e, exc_info=True)
        raise
    finally:
        spark.stop()


if __name__ == "__main__":
    run()

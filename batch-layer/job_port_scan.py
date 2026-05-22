
import logging
from pyspark.sql import SparkSession, DataFrame
from pyspark.sql import functions as F

from spark_config import create_session, hdfs_path
import hbase_writer

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s - %(message)s")
logger = logging.getLogger(__name__)

PORT_SCAN_THRESHOLD = 20
TIME_WINDOW = "5 minutes"


def detect(spark: SparkSession) -> DataFrame:
    """Core detection logic."""
    logs = spark.read.parquet(hdfs_path("/data/cybersecurity/logs"))

    result = (
        logs.filter(F.col("protocol") == "TCP")
        .groupBy("source_ip", F.window(F.col("timestamp"), TIME_WINDOW))
        .agg(
            F.countDistinct("dest_ip").alias("distinct_targets"),
            F.count("*").alias("event_count"),
            F.first("log_type").alias("log_type"),
        )
        .filter(F.col("distinct_targets") > PORT_SCAN_THRESHOLD)
        .withColumn("attack_type", F.lit("PORT_SCAN"))
        .withColumn(
            "threat_score",
            F.least(F.lit(100),
                    (F.lit(60) + F.col("distinct_targets") - F.lit(PORT_SCAN_THRESHOLD)).cast("int")),
        )
        .withColumn(
            "severity",
            F.when(F.col("distinct_targets") > 100, "CRITICAL")
            .when(F.col("distinct_targets") > 50, "HIGH")
            .otherwise("MEDIUM"),
        )
        .withColumn("window_start", F.col("window.start"))
        .withColumn("window_end", F.col("window.end"))
        .drop("window")
        .orderBy(F.col("distinct_targets").desc())
    )
    return result


def run():
    logger.info("=== Starting Job: Port Scan Detection ===")
    spark = create_session("PortScanDetector")
    spark.sparkContext.setLogLevel("WARN")

    try:
        result = detect(spark)
        result.show(20, truncate=False)

        out_path = hdfs_path("/data/cybersecurity/batch/port_scans")
        result.write.mode("overwrite").parquet(out_path)
        logger.info("Saved to HDFS: %s", out_path)

        rows = [row.asDict() for row in result.collect()]
        hbase_writer.write_attack_pattern(rows, "PORT_SCAN")

        count = len(rows)
        logger.info("=== Job PortScanDetection completed: %d scans detected ===", count)
    except Exception as e:
        logger.error("Job failed: %s", e, exc_info=True)
        raise
    finally:
        spark.stop()


if __name__ == "__main__":
    run()

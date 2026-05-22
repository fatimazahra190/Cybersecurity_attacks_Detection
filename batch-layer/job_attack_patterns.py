import logging
from pyspark.sql import SparkSession, DataFrame
from pyspark.sql import functions as F

from spark_config import create_session, hdfs_path
import hbase_writer

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s - %(message)s")
logger = logging.getLogger(__name__)

# ── Regex patterns ────────────────────────────────────────────────────
SQLI_PATTERN = r"(?i)('\s+OR|UNION\s+SELECT|1=1--|DROP\s+TABLE|xp_cmdshell|EXEC\(|INSERT\s+INTO|DELETE\s+FROM)"
XSS_PATTERN  = r"(?i)(<script|javascript:|onerror=|alert\(|document\.cookie|eval\(|onload=)"
LFI_PATTERN  = r"(?i)(\.\.\/\.\.\.|/etc/passwd|/etc/shadow|/proc/self|%2e%2e%2f)"
TOOL_PATTERN = r"(?i)(sqlmap|nikto|nmap|masscan|burpsuite|dirbuster|hydra|metasploit|w3af|acunetix|openvas)"


def detect(spark: SparkSession) -> DataFrame:
    """Core detection logic - testable independently."""
    logs = spark.read.parquet(hdfs_path("/data/cybersecurity/logs"))

    sqli_col = F.col("request_path").rlike(SQLI_PATTERN)
    xss_col  = F.col("request_path").rlike(XSS_PATTERN)
    lfi_col  = F.col("request_path").rlike(LFI_PATTERN)
    tool_col = F.col("user_agent").rlike(TOOL_PATTERN)

    result = (
        logs.filter(sqli_col | xss_col | lfi_col | tool_col)
        .withColumn("is_sqli", sqli_col)
        .withColumn("is_xss",  xss_col)
        .withColumn("is_lfi",  lfi_col)
        .withColumn("is_tool", tool_col)
        .withColumn(
            "attack_category",
            F.when(tool_col, "TOOL_DETECTED")
            .when(sqli_col, "SQLI")
            .when(xss_col,  "XSS")
            .when(lfi_col,  "LFI")
            .otherwise("UNKNOWN"),
        )
        .withColumn(
            "threat_score",
            F.when(tool_col, 95)
            .when(sqli_col, 85)
            .when(xss_col,  75)
            .when(lfi_col,  70)
            .otherwise(60),
        )
        .withColumn("severity", F.lit("CRITICAL"))
        .orderBy(F.col("threat_score").desc(), F.col("timestamp").desc())
    )
    return result


def run():
    logger.info("=== Starting Job: Attack Pattern Detection ===")
    spark = create_session("AttackPatternDetector")
    spark.sparkContext.setLogLevel("WARN")

    try:
        result = detect(spark)
        result.show(20, truncate=False)

        # Distribution by category
        logger.info("Attack category distribution:")
        result.groupBy("attack_category").count().show()

        out_path = hdfs_path("/data/cybersecurity/batch/attack_patterns")
        result.write.mode("overwrite").parquet(out_path)
        logger.info("Saved to HDFS: %s", out_path)

        # Collect only top 200 rows for HBase to avoid OOM on large datasets
        top200 = result.limit(200)
        rows = [row.asDict() for row in top200.collect()]
        hbase_writer.write_attack_pattern(rows, "INJECTION")

        logger.info("=== Job AttackPatternDetector completed — saved to HDFS ===")
    except Exception as e:
        logger.error("Job failed: %s", e, exc_info=True)
        raise
    finally:
        spark.stop()


if __name__ == "__main__":
    run()


import argparse
import logging
import sys
from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import (
    StructType, StructField,
    StringType, LongType, TimestampType
)

from spark_config import create_session, hdfs_path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

SCHEMA = StructType([
    StructField("timestamp",         TimestampType(), False),
    StructField("source_ip",         StringType(),    False),
    StructField("dest_ip",           StringType(),    False),
    StructField("protocol",          StringType(),    False),
    StructField("action",            StringType(),    False),
    StructField("threat_label",      StringType(),    False),
    StructField("log_type",          StringType(),    False),
    StructField("bytes_transferred", LongType(),      True),
    StructField("user_agent",        StringType(),    True),
    StructField("request_path",      StringType(),    True),
])


def run(input_path: str):
    output_path = hdfs_path("/data/cybersecurity/logs")
    logger.info("Input : %s", input_path)
    logger.info("Output: %s", output_path)

    spark = create_session("ConvertToParquet")
    spark.sparkContext.setLogLevel("WARN")

    try:
        # Try with explicit schema first; fall back to inferred
        try:
            df = (
                spark.read
                .schema(SCHEMA)
                .option("header", "true")
                .option("timestampFormat", "yyyy-MM-dd HH:mm:ss")
                .option("mode", "DROPMALFORMED")
                .csv(input_path)
            )
        except Exception:
            logger.warning("Schema mismatch – falling back to inferred schema")
            df = (
                spark.read
                .option("header", "true")
                .option("inferSchema", "true")
                .csv(input_path)
            )

        count = df.count()
        logger.info("Read %d rows from CSV.", count)
        if count == 0:
            logger.error("CSV is empty or path is wrong. Aborting.")
            sys.exit(1)

        df.printSchema()

        # Add partition columns
        partitioned = (
            df
            .withColumn("year",  F.year(F.col("timestamp")).cast("string"))
            .withColumn("month", F.lpad(F.month(F.col("timestamp")).cast("string"), 2, "0"))
            .withColumn("day",   F.lpad(F.dayofmonth(F.col("timestamp")).cast("string"), 2, "0"))
        )

        (
            partitioned.write
            .mode("overwrite")
            .partitionBy("year", "month", "day")
            .parquet(output_path)
        )

        logger.info("Conversion complete. Data available at: %s", output_path)
    except Exception as e:
        logger.error("Conversion failed: %s", e, exc_info=True)
        sys.exit(1)
    finally:
        spark.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert CSV to Parquet in HDFS")
    parser.add_argument(
        "--input",
        default="/app/data/cybersecurity_threat_detection_logs.csv",
        help="Path to the CSV file (local or HDFS)"
    )
    args = parser.parse_args()
    run(args.input)

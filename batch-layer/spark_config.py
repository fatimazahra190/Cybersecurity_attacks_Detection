import os
from pyspark.sql import SparkSession


HADOOP_HOST = os.getenv("HADOOP_NAMENODE", "namenode")
HADOOP_PORT = os.getenv("HADOOP_PORT", "9000")
HBASE_HOST  = os.getenv("HBASE_HOST", "hbase")
ZOOKEEPER_HOST = os.getenv("ZOOKEEPER_HOST", "zookeeper")

HDFS_BASE = f"hdfs://{HADOOP_HOST}:{HADOOP_PORT}"


def create_session(app_name: str) -> SparkSession:
    """Create and return a configured SparkSession for batch jobs."""
    return (
        SparkSession.builder
        .appName(app_name)
        .master("local[*]")
        .config("spark.hadoop.fs.defaultFS", HDFS_BASE)
        .config("spark.sql.shuffle.partitions", "4")
        .config("spark.network.timeout", "300s")
        .config("spark.executor.heartbeatInterval", "60s")
        .config("spark.ui.enabled", "false")
        .config("spark.sql.legacy.timeParserPolicy", "LEGACY")
        .config("hbase.zookeeper.quorum", ZOOKEEPER_HOST)
        .config("hbase.zookeeper.property.clientPort", "2181")
        .getOrCreate()
    )


def hdfs_path(relative: str) -> str:
    """Build a full HDFS path from a relative one."""
    return f"{HDFS_BASE}{relative}"


import pytest
from datetime import datetime
from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import (
    StructType, StructField, StringType, LongType, TimestampType
)

# ── Shared SparkSession ───────────────────────────────────────────────
@pytest.fixture(scope="module")
def spark():
    s = (
        SparkSession.builder
        .appName("BatchTests")
        .master("local[1]")
        .config("spark.sql.shuffle.partitions", "1")
        .config("spark.ui.enabled", "false")
        .getOrCreate()
    )
    s.sparkContext.setLogLevel("ERROR")
    yield s
    s.stop()


SCHEMA = StructType([
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

TS = datetime(2023, 10, 15, 14, 0, 0)


# ═══════════════════════════════════════════════════════════════════════
# TopMaliciousIPs tests
# ═══════════════════════════════════════════════════════════════════════
class TestTopMaliciousIPs:

    def _data(self, spark):
        rows = [
            (TS, "192.168.1.100", "10.0.0.1", "TCP",  "blocked", "malicious",  "firewall",    1024, "sqlmap/1.7", "/admin"),
            (TS, "192.168.1.100", "10.0.0.2", "TCP",  "blocked", "malicious",  "firewall",    2048, "sqlmap/1.7", "/admin"),
            (TS, "192.168.1.100", "10.0.0.3", "HTTP", "blocked", "malicious",  "ids",          512, "sqlmap/1.7", "/login"),
            (TS, "192.168.1.100", "10.0.0.4", "HTTP", "blocked", "malicious",  "firewall",     768, "sqlmap/1.7", "/wp"),
            (TS, "192.168.1.100", "10.0.0.5", "TCP",  "blocked", "malicious",  "firewall",     256, "sqlmap/1.7", "/phpmyadmin"),
            (TS, "192.168.1.200", "10.0.0.10","HTTP", "allowed", "suspicious", "application",  512, "Mozilla", "/s"),
            (TS, "192.168.1.200", "10.0.0.11","HTTP", "allowed", "suspicious", "application", 1024, "Mozilla", "/s?q=1"),
            (TS, "192.168.1.200", "10.0.0.12","HTTP", "blocked", "suspicious", "ids",          256, "nikto/2",  "/admin"),
            (TS, "192.168.1.50",  "10.0.0.20","HTTP", "allowed", "benign",     "application", 1500, "Mozilla", "/index.html"),
        ]
        return spark.createDataFrame(rows, SCHEMA)

    def test_filters_suspicious_and_malicious(self, spark):
        df = self._data(spark)
        filtered = df.filter(F.col("threat_label").isin("suspicious", "malicious"))
        assert filtered.count() == 8

    def test_benign_excluded(self, spark):
        df = self._data(spark)
        filtered = df.filter(F.col("threat_label").isin("suspicious", "malicious"))
        benign_in_result = filtered.filter(F.col("source_ip") == "192.168.1.50").count()
        assert benign_in_result == 0

    def test_reputation_score_in_range(self, spark):
        # 5 malicious / 5 total → score = min(100, 5*10/5*100) = 100
        malicious, suspicious, total = 5, 0, 5
        score = min(100, int((malicious * 10 + suspicious * 5) / total * 100))
        assert 0 <= score <= 100

    def test_score_formula_mixed(self, spark):
        # 3 malicious + 2 suspicious / 5 total
        score = min(100, int((3 * 10 + 2 * 5) / 5 * 100))
        assert score == 80


# ═══════════════════════════════════════════════════════════════════════
# BruteForce detection tests (logic only, no streaming)
# ═══════════════════════════════════════════════════════════════════════
class TestBruteForceLogic:
    THRESHOLD = 5

    def _simulate(self, spark, rows):
        df = spark.createDataFrame(rows, SCHEMA)
        return (
            df.filter(F.col("action") == "blocked")
            .groupBy("source_ip")
            .agg(
                F.count("*").alias("blocked_count"),
                F.first("user_agent").alias("user_agent"),
                F.sum("bytes_transferred").alias("bytes_total"),
            )
            .filter(F.col("blocked_count") > self.THRESHOLD)
            .withColumn(
                "threat_score",
                F.least(F.lit(100),
                        (F.lit(70) + (F.col("blocked_count") - self.THRESHOLD) * 2).cast("int"))
            )
            .withColumn(
                "severity",
                F.when(F.col("blocked_count") > 10, "CRITICAL").otherwise("HIGH")
            )
        )

    def test_6_blocked_triggers_alert(self, spark):
        rows = [(TS, "10.0.0.1", "192.168.0.1", "HTTP", "blocked", "malicious",
                 "firewall", 512, "hydra/9.4", "/login")] * 6
        result = self._simulate(spark, rows)
        assert result.count() == 1
        row = result.first()
        assert row["severity"] == "HIGH"
        assert 70 <= row["threat_score"] <= 100

    def test_4_blocked_no_alert(self, spark):
        rows = [(TS, "10.0.0.2", "192.168.0.1", "HTTP", "blocked", "malicious",
                 "firewall", 512, "hydra", "/login")] * 4
        assert self._simulate(spark, rows).count() == 0

    def test_11_blocked_critical(self, spark):
        rows = [(TS, "10.0.0.3", "192.168.0.1", "HTTP", "blocked", "malicious",
                 "firewall", 512, "hydra", "/login")] * 11
        result = self._simulate(spark, rows)
        assert result.count() == 1
        assert result.first()["severity"] == "CRITICAL"

    def test_only_blocked_actions_count(self, spark):
        # 3 blocked + 5 allowed — should NOT trigger
        blocked = [(TS, "10.0.0.4", "192.168.0.1", "HTTP", "blocked", "malicious",
                    "firewall", 100, "curl", "/")] * 3
        allowed = [(TS, "10.0.0.4", "192.168.0.1", "HTTP", "allowed", "benign",
                    "application", 200, "Mozilla", "/index")] * 5
        assert self._simulate(spark, blocked + allowed).count() == 0


# ═══════════════════════════════════════════════════════════════════════
# Signature/Pattern detection tests
# ═══════════════════════════════════════════════════════════════════════
class TestSignatureDetection:
    TOOL = r"(?i)(sqlmap|nikto|nmap|masscan|burpsuite|dirbuster|hydra|metasploit)"
    SQLI = r"(?i)('\s+OR|UNION\s+SELECT|1=1--|DROP\s+TABLE|xp_cmdshell)"
    XSS  = r"(?i)(<script|javascript:|onerror=|alert\(|document\.cookie)"

    def _df(self, spark, user_agent="", request_path="/"):
        rows = [(TS, "10.0.0.1", "192.168.1.1", "HTTP", "blocked", "malicious",
                 "ids", 1024, user_agent, request_path)]
        return spark.createDataFrame(rows, SCHEMA)

    def test_sqlmap_detected(self, spark):
        df = self._df(spark, user_agent="sqlmap/1.7.8#stable")
        assert df.filter(F.col("user_agent").rlike(self.TOOL)).count() == 1

    def test_nikto_detected(self, spark):
        df = self._df(spark, user_agent="nikto/2.1.6")
        assert df.filter(F.col("user_agent").rlike(self.TOOL)).count() == 1

    def test_sqli_in_path(self, spark):
        df = self._df(spark, request_path="/p?id=1 UNION SELECT user,pass FROM users--")
        assert df.filter(F.col("request_path").rlike(self.SQLI)).count() == 1

    def test_xss_in_path(self, spark):
        df = self._df(spark, request_path="/s?q=<script>alert(1)</script>")
        assert df.filter(F.col("request_path").rlike(self.XSS)).count() == 1

    def test_normal_agent_not_flagged(self, spark):
        df = self._df(spark, user_agent="Mozilla/5.0 (Windows NT 10.0) Chrome/118.0", request_path="/home")
        tool = df.filter(F.col("user_agent").rlike(self.TOOL)).count()
        sqli = df.filter(F.col("request_path").rlike(self.SQLI)).count()
        xss  = df.filter(F.col("request_path").rlike(self.XSS)).count()
        assert tool == 0 and sqli == 0 and xss == 0


# ═══════════════════════════════════════════════════════════════════════
# Port Scan detection tests
# ═══════════════════════════════════════════════════════════════════════
class TestPortScanDetection:
    THRESHOLD = 20

    def test_25_targets_detected(self, spark):
        rows = [
            (TS, "192.168.1.99", f"10.0.0.{i}", "TCP", "blocked",
             "suspicious", "firewall", 64, "nmap/7.94", "/scan")
            for i in range(1, 26)
        ]
        df = spark.createDataFrame(rows, SCHEMA)
        distinct = df.filter(F.col("protocol") == "TCP") \
                     .filter(F.col("source_ip") == "192.168.1.99") \
                     .select("dest_ip").distinct().count()
        assert distinct >= 25
        assert distinct > self.THRESHOLD

    def test_5_targets_no_alert(self, spark):
        rows = [
            (TS, "192.168.1.50", f"10.0.0.{i}", "TCP", "allowed",
             "benign", "firewall", 1024, "Mozilla", "/")
            for i in range(1, 6)
        ]
        df = spark.createDataFrame(rows, SCHEMA)
        distinct = df.filter(F.col("protocol") == "TCP").select("dest_ip").distinct().count()
        assert distinct <= self.THRESHOLD

    def test_only_tcp_filtered(self, spark):
        rows = [
            (TS, "10.0.0.1", "10.0.0.100", "TCP",  "blocked", "suspicious", "firewall", 100, "nmap", "/"),
            (TS, "10.0.0.1", "10.0.0.101", "HTTP", "blocked", "suspicious", "ids",      200, "curl", "/api"),
            (TS, "10.0.0.1", "10.0.0.102", "SSH",  "blocked", "malicious",  "firewall", 300, "hydra","/"),
        ]
        df = spark.createDataFrame(rows, SCHEMA)
        assert df.filter(F.col("protocol") == "TCP").count() == 1


# ═══════════════════════════════════════════════════════════════════════
# ThreatFusion logic tests (pure Python, no Spark)
# ═══════════════════════════════════════════════════════════════════════
class TestThreatFusionLogic:
    """Test recommendation and confidence logic without service mocks."""

    def _rec(self, batch_score, alerts):
        if batch_score > 80 and alerts >= 1:
            return "BLOCK"
        if batch_score >= 50:
            return "MONITOR"
        if alerts > 0:
            return "MONITOR"
        return "ALLOW"

    def _conf(self, batch, speed):
        return round(min(1.0, (batch * 0.4 + speed * 0.6) / 100.0), 2)

    def test_block_high_score_with_alerts(self):
        assert self._rec(87, 3) == "BLOCK"

    def test_block_score_81(self):
        assert self._rec(81, 1) == "BLOCK"

    def test_monitor_medium_no_alerts(self):
        assert self._rec(65, 0) == "MONITOR"

    def test_monitor_high_no_alerts(self):
        assert self._rec(85, 0) == "MONITOR"

    def test_monitor_score_50(self):
        assert self._rec(50, 0) == "MONITOR"

    def test_allow_low_no_alerts(self):
        assert self._rec(0, 0) == "ALLOW"

    def test_allow_score_49(self):
        assert self._rec(49, 0) == "ALLOW"

    def test_monitor_unknown_ip_with_alerts(self):
        # IP not in batch but has active alerts → MONITOR
        assert self._rec(0, 2) == "MONITOR"

    def test_confidence_calculation(self):
        # batch=80, speed=100 → (32+60)/100 = 0.92
        assert self._conf(80, 100) == 0.92

    def test_confidence_capped_at_1(self):
        assert self._conf(100, 100) <= 1.0

    def test_confidence_zero(self):
        assert self._conf(0, 0) == 0.0

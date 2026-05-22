#!/usr/bin/env python3
"""
Kafka Producer — Simulates real-time cybersecurity log streaming.
Reads the dataset CSV and publishes each row to 'cybersecurity-logs'.

Usage:
    python kafka_producer.py --input data.csv [--rate 10] [--loop] [--demo]
"""
import argparse
import csv
import json
import os
import signal
import sys
import time
from datetime import datetime, timezone

from kafka import KafkaProducer
from kafka.errors import NoBrokersAvailable

KAFKA_SERVERS = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
TOPIC = "cybersecurity-logs"
DEFAULT_RATE = 10
DEFAULT_INPUT = "/app/data/cybersecurity_threat_detection_logs.csv"

# Partition 0=firewall, 1=ids, 2=application
PARTITION_MAP = {"firewall": 0, "ids": 1, "application": 2}

running = True


def _handle_signal(sig, frame):
    global running
    print("\n⛔ Stopping producer…")
    running = False


signal.signal(signal.SIGINT, _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


def _create_producer() -> KafkaProducer:
    print(f"🔌 Connecting to Kafka: {KAFKA_SERVERS}")
    for attempt in range(15):
        try:
            p = KafkaProducer(
                bootstrap_servers=KAFKA_SERVERS,
                value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
                key_serializer=lambda k: k.encode("utf-8") if k else None,
                acks="all",
                retries=3,
                compression_type="gzip",
                batch_size=16384,
                linger_ms=100,
                request_timeout_ms=30000,
            )
            print("✅ Connected to Kafka.")
            return p
        except NoBrokersAvailable:
            wait = min((attempt + 1) * 3, 30)
            print(f"   Kafka unavailable. Retry {attempt + 1}/15 in {wait}s…")
            time.sleep(wait)
    print("❌ Could not connect to Kafka.")
    sys.exit(1)


def _normalize_row(row: dict) -> dict:
    ts = row.get("timestamp", "")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            ts = datetime.strptime(ts, fmt).strftime("%Y-%m-%dT%H:%M:%SZ")
            break
        except ValueError:
            pass

    try:
        byt = int(row.get("bytes_transferred") or 0)
    except (ValueError, TypeError):
        byt = 0

    return {
        "timestamp":         ts or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_ip":         row.get("source_ip", "0.0.0.0"),
        "dest_ip":           row.get("dest_ip", "0.0.0.0"),
        "protocol":          row.get("protocol", "HTTP"),
        "action":            row.get("action", "allowed"),
        "threat_label":      row.get("threat_label", "benign"),
        "log_type":          row.get("log_type", "firewall"),
        "bytes_transferred": byt,
        "user_agent":        row.get("user_agent") or "",
        "request_path":      row.get("request_path") or "/",
    }


def produce(input_file: str, rate: int, loop: bool = False):
    producer = _create_producer()
    interval = 1.0 / max(rate, 1)
    sent = 0
    errors = 0
    t0 = time.time()
    pass_no = 0

    print(f"📂 File: {input_file}  |  Topic: {TOPIC}  |  Rate: {rate} msg/s  |  Loop: {loop}")

    while running:
        pass_no += 1
        if pass_no > 1:
            print(f"\n🔁 Pass {pass_no}…")
        try:
            with open(input_file, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if not running:
                        break
                    msg = _normalize_row(row)
                    log_type = msg.get("log_type", "firewall")
                    partition = PARTITION_MAP.get(log_type, 0)
                    try:
                        producer.send(TOPIC, key=log_type, value=msg, partition=partition)
                        sent += 1
                    except Exception:
                        errors += 1

                    if sent % 1000 == 0:
                        elapsed = time.time() - t0
                        actual = sent / elapsed if elapsed > 0 else 0
                        print(f"   📊 Sent: {sent:,}  |  Rate: {actual:.1f} msg/s  |  Errors: {errors}")

                    time.sleep(interval)
        except FileNotFoundError:
            print(f"❌ File not found: {input_file}")
            sys.exit(1)

        if not loop:
            break

    print("\n⏳ Flushing…")
    producer.flush(timeout=30)
    producer.close()
    elapsed = time.time() - t0
    print(f"✅ Done. Sent: {sent:,}  Errors: {errors}  Duration: {elapsed:.1f}s")


def send_demo_scenario():
    """Send 3 attack scenarios for quick testing."""
    producer = _create_producer()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print("\n🎯 Sending demo attack scenarios…")

    # Scenario 1: Brute-force (8 blocked requests)
    for i in range(8):
        msg = {
            "timestamp": now, "source_ip": "10.10.10.1",
            "dest_ip": "192.168.0.10", "protocol": "HTTP",
            "action": "blocked", "threat_label": "malicious",
            "log_type": "firewall", "bytes_transferred": 512,
            "user_agent": "hydra/9.4", "request_path": "/admin/login",
        }
        producer.send(TOPIC, key="firewall", value=msg, partition=0)
        print(f"   BruteForce {i+1}/8 -> 10.10.10.1")
        time.sleep(0.3)

    # Scenario 2: SQLi via sqlmap
    producer.send(TOPIC, key="ids", value={
        "timestamp": now, "source_ip": "10.20.30.40",
        "dest_ip": "192.168.0.20", "protocol": "HTTP",
        "action": "blocked", "threat_label": "malicious",
        "log_type": "ids", "bytes_transferred": 2048,
        "user_agent": "sqlmap/1.7.8#stable",
        "request_path": "/product.php?id=1' OR '1'='1",
    }, partition=1)
    print("   SQLi via sqlmap -> 10.20.30.40")

    # Scenario 3: Volume anomaly (15 MB)
    producer.send(TOPIC, key="firewall", value={
        "timestamp": now, "source_ip": "172.16.0.5",
        "dest_ip": "8.8.8.8", "protocol": "TCP",
        "action": "allowed", "threat_label": "suspicious",
        "log_type": "firewall", "bytes_transferred": 15728640,
        "user_agent": "", "request_path": "/data/export",
    }, partition=0)
    print("   Volume anomaly 15MB -> 172.16.0.5")

    producer.flush(timeout=10)
    producer.close()
    print("\n✅ Demo scenarios sent. Check dashboard in ~5 seconds.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kafka Producer — CyberSec Logs")
    parser.add_argument("--input",  default=DEFAULT_INPUT)
    parser.add_argument("--rate",   type=int, default=DEFAULT_RATE)
    parser.add_argument("--loop",   action="store_true")
    parser.add_argument("--demo",   action="store_true")
    args = parser.parse_args()

    if args.demo:
        send_demo_scenario()
    else:
        produce(args.input, args.rate, args.loop)

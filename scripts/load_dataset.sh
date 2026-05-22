#!/usr/bin/env bash
set -euo pipefail

CSV_PATH="${1:-}"
if [[ -z "$CSV_PATH" ]]; then
    echo "Usage: $0 /path/to/cybersecurity_threat_detection_logs.csv"
    exit 1
fi

if [[ ! -f "$CSV_PATH" ]]; then
    echo "❌ File not found: $CSV_PATH"
    exit 1
fi

echo "📂 Loading dataset: $CSV_PATH"
echo ""

# Copy CSV into the spark container
echo "Copying CSV to spark container…"
docker cp "$CSV_PATH" py-spark:/app/data/cybersecurity_threat_detection_logs.csv
echo "✅ CSV copied."

# Convert to Parquet via Spark
echo ""
echo "Converting CSV → Parquet in HDFS (this may take 2-5 min)…"
docker exec py-spark python /app/batch-layer/convert_to_parquet.py \
    --input file:///app/data/cybersecurity_threat_detection_logs.csv

echo ""
echo "✅ Dataset loaded and partitioned in HDFS."
echo "   Run ./scripts/run_batch.sh to execute analysis jobs."

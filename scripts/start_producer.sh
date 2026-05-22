set -euo pipefail

RATE="${1:-10}"
echo " Starting Kafka producer at ${RATE} msg/s…"

docker exec -d producer python /app/kafka_producer.py \
    --input /app/data/cybersecurity_threat_detection_logs.csv \
    --rate "$RATE" \
    --loop

echo "✅ Producer started in background."
echo "   Monitor: docker logs -f producer"

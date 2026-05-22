#!/usr/bin/env bash
# =============================================================================
#  demo.sh — End-to-end demo: inject attack scenarios and verify alerts
#  Estimated duration: ~2 min
# =============================================================================
set -euo pipefail

API="http://localhost:8080"

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   CyberSec Lambda — End-to-End Demo                     ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Check API is up
if ! curl -sf "$API/health" | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if d.get('components',{}).get('api')=='UP' else 1)" 2>/dev/null; then
    echo "❌ API not reachable at $API"
    echo "   Make sure 'docker compose up -d' and 'init.sh' have been run."
    exit 1
fi
echo "✅ API is reachable."
echo ""

# ── Scenario 1: Brute-Force ───────────────────────────────────────────
echo "━━━━ SCENARIO 1: Brute-Force (8 blocked requests from 10.10.10.1) ━━━━"
NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
for i in $(seq 1 8); do
    MSG="{\"timestamp\":\"$NOW\",\"source_ip\":\"10.10.10.1\",\"dest_ip\":\"192.168.0.10\",\"protocol\":\"HTTP\",\"action\":\"blocked\",\"threat_label\":\"malicious\",\"log_type\":\"firewall\",\"bytes_transferred\":512,\"user_agent\":\"hydra/9.4\",\"request_path\":\"/admin/login\"}"
    echo "$MSG" | docker exec -i py-kafka kafka-console-producer \
        --bootstrap-server localhost:9092 \
        --topic cybersecurity-logs 2>/dev/null
    echo "   Attempt $i/8 sent → 10.10.10.1"
    sleep 0.4
done

# ── Scenario 2: SQLi ──────────────────────────────────────────────────
echo ""
echo "━━━━ SCENARIO 2: SQL Injection via sqlmap (10.20.30.40) ━━━━"
SQLI="{\"timestamp\":\"$NOW\",\"source_ip\":\"10.20.30.40\",\"dest_ip\":\"192.168.0.20\",\"protocol\":\"HTTP\",\"action\":\"blocked\",\"threat_label\":\"malicious\",\"log_type\":\"ids\",\"bytes_transferred\":2048,\"user_agent\":\"sqlmap/1.7.8#stable\",\"request_path\":\"/product.php?id=1' OR '1'='1\"}"
echo "$SQLI" | docker exec -i py-kafka kafka-console-producer \
    --bootstrap-server localhost:9092 --topic cybersecurity-logs 2>/dev/null
echo "   SQLi event sent → 10.20.30.40"

# ── Scenario 3: Volume anomaly ─────────────────────────────────────────
echo ""
echo "━━━━ SCENARIO 3: Volume Anomaly 15 MB (172.16.0.5) ━━━━"
VOL="{\"timestamp\":\"$NOW\",\"source_ip\":\"172.16.0.5\",\"dest_ip\":\"8.8.8.8\",\"protocol\":\"TCP\",\"action\":\"allowed\",\"threat_label\":\"suspicious\",\"log_type\":\"firewall\",\"bytes_transferred\":15728640,\"user_agent\":\"\",\"request_path\":\"/data/export\"}"
echo "$VOL" | docker exec -i py-kafka kafka-console-producer \
    --bootstrap-server localhost:9092 --topic cybersecurity-logs 2>/dev/null
echo "   Volume event sent → 172.16.0.5"

# ── Wait for Spark Streaming to process ──────────────────────────────
echo ""
echo "Waiting 8 seconds for Spark Streaming to process events…"
sleep 8

# ── Verify results ─────────────────────────────────────────────────────
echo ""
echo "━━━━ RESULTS: Active Alerts ━━━━"
ALERTS=$(curl -s "$API/threats/active")
COUNT=$(echo "$ALERTS" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "?")
echo "   Active alerts found: $COUNT"

echo ""
echo "━━━━ IP PROFILE: 10.10.10.1 (brute-force attacker) ━━━━"
curl -s "$API/threats/ip/10.10.10.1" | python3 -m json.tool 2>/dev/null || \
    curl -s "$API/threats/ip/10.10.10.1"

echo ""
echo "━━━━ IP PROFILE: 10.20.30.40 (SQLi attacker) ━━━━"
curl -s "$API/threats/ip/10.20.30.40" | python3 -m json.tool 2>/dev/null || \
    curl -s "$API/threats/ip/10.20.30.40"

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   ✅ Demo complete!                                      ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "  Dashboard : http://localhost:3000"
echo "  API       : http://localhost:8080/threats/active"
echo ""

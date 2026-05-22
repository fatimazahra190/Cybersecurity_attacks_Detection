set -uo pipefail

API="http://localhost:8080"
PASS=0; FAIL=0; WARN=0

grn='\033[0;32m'; red='\033[0;31m'; yel='\033[1;33m'; cyn='\033[0;36m'; nc='\033[0m'
chk()  { PASS=$((PASS+1)); echo -e "${grn}  ✅ PASS${nc} — $1"; }
fail() { FAIL=$((FAIL+1)); echo -e "${red}  ❌ FAIL${nc} — $1"; }
warn() { WARN=$((WARN+1)); echo -e "${yel}  ⚠️  WARN${nc} — $1"; }
sec()  { echo ""; echo -e "${cyn}━━ $1 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${nc}"; }

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   CyberSec Lambda — Health Checklist                    ║"
echo "╚══════════════════════════════════════════════════════════╝"

# ── Docker containers ─────────────────────────────────────────────────
sec "1. Docker Containers"
for c in zookeeper kafka namenode datanode cassandra hbase api streaming dashboard; do
    STATE=$(docker inspect --format='{{.State.Status}}' "$c" 2>/dev/null || echo "missing")
    if [[ "$STATE" == "running" ]]; then chk "Container '$c' is running"
    else fail "Container '$c' is $STATE"; fi
done

# ── Network reachability ──────────────────────────────────────────────
sec "2. Network Reachability"
curl -sf "$API/health" &>/dev/null && chk "API /health responds" || fail "API /health unreachable"
curl -sf "http://localhost:9870" &>/dev/null && chk "HDFS UI (port 9870)" || warn "HDFS UI not reachable"
curl -sf "http://localhost:16010" &>/dev/null && chk "HBase UI (port 16010)" || warn "HBase UI not reachable"
curl -sf "http://localhost:3000" &>/dev/null && chk "Dashboard (port 3000)" || warn "Dashboard not reachable"

# ── API health response ────────────────────────────────────────────────
sec "3. API Health Details"
HEALTH=$(curl -sf "$API/health" 2>/dev/null || echo '{}')
API_UP=$(echo "$HEALTH" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('components',{}).get('api','DOWN'))" 2>/dev/null)
HBASE_UP=$(echo "$HEALTH" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('components',{}).get('hbase','DOWN'))" 2>/dev/null)
CASS_UP=$(echo "$HEALTH" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('components',{}).get('cassandra','DOWN'))" 2>/dev/null)
[[ "$API_UP"   == "UP" ]] && chk "API component UP"        || fail "API component DOWN"
[[ "$HBASE_UP" == "UP" ]] && chk "HBase component UP"      || fail "HBase component DOWN"
[[ "$CASS_UP"  == "UP" ]] && chk "Cassandra component UP"  || fail "Cassandra component DOWN"

# ── Kafka ─────────────────────────────────────────────────────────────
sec "4. Kafka"
TOPIC=$(docker exec py-kafka kafka-topics --bootstrap-server localhost:9092 --list 2>/dev/null | grep "cybersecurity-logs")
[[ -n "$TOPIC" ]] && chk "Topic 'cybersecurity-logs' exists" || fail "Topic 'cybersecurity-logs' missing"
PARTS=$(docker exec py-kafka kafka-topics --describe --topic cybersecurity-logs \
    --bootstrap-server localhost:9092 2>/dev/null | grep -c "Partition:")
[[ "$PARTS" -ge 3 ]] && chk "Topic has 3 partitions" || warn "Expected 3 partitions, got $PARTS"

# ── HDFS ─────────────────────────────────────────────────────────────
sec "5. HDFS"
for DIR in /data/cybersecurity/logs /data/cybersecurity/batch; do
    docker exec py-namenode hdfs dfs -ls "$DIR" &>/dev/null && \
        chk "HDFS directory $DIR exists" || fail "HDFS directory $DIR missing"
done
SAFEMODE=$(docker exec py-namenode hdfs dfsadmin -safemode get 2>/dev/null | grep -o "OFF\|ON")
[[ "$SAFEMODE" == "OFF" ]] && chk "HDFS safe mode OFF" || fail "HDFS still in safe mode"

# ── Cassandra ─────────────────────────────────────────────────────────
sec "6. Cassandra Schema"
TABLE=$(docker exec py-cassandra cqlsh -e "DESCRIBE TABLE cybersecurity.active_threats" 2>/dev/null | head -1)
[[ -n "$TABLE" ]] && chk "Table active_threats exists" || fail "Table active_threats missing"

# ── HBase ─────────────────────────────────────────────────────────────
sec "7. HBase Tables"
TABLES=$(docker exec py-hbase hbase shell <<< "list" 2>/dev/null)
for T in ip_reputation attack_patterns threat_timeline; do
    echo "$TABLES" | grep -q "$T" && chk "HBase table '$T' exists" || fail "HBase table '$T' missing"
done

# ── API endpoints ─────────────────────────────────────────────────────
sec "8. API Endpoints"
for EP in "/threats/active" "/threats/stats" "/threats/timeline"; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" "$API$EP")
    [[ "$CODE" == "200" ]] && chk "GET $EP returns 200" || fail "GET $EP returned $CODE"
done
# IP profile for unknown IP should return 200 with ALLOW
IP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$API/threats/ip/1.2.3.4")
[[ "$IP_CODE" == "200" ]] && chk "GET /threats/ip/1.2.3.4 returns 200" || fail "IP profile returned $IP_CODE"

# ── Demo scenario ─────────────────────────────────────────────────────
sec "9. Functional Test — Demo Scenario"
echo "   Sending a demo brute-force scenario (requires streaming to be running)…"
NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
for i in $(seq 1 6); do
    MSG="{\"timestamp\":\"$NOW\",\"source_ip\":\"99.88.77.66\",\"dest_ip\":\"10.0.0.1\",\"protocol\":\"HTTP\",\"action\":\"blocked\",\"threat_label\":\"malicious\",\"log_type\":\"firewall\",\"bytes_transferred\":512,\"user_agent\":\"hydra/9.4\",\"request_path\":\"/login\"}"
    echo "$MSG" | docker exec -i py-kafka kafka-console-producer \
        --bootstrap-server localhost:9092 --topic cybersecurity-logs 2>/dev/null
done
echo "   Waiting 8 seconds for Spark to process…"
sleep 8
ALERT_COUNT=$(curl -sf "$API/threats/active" 2>/dev/null | \
    python3 -c "import sys,json; a=json.load(sys.stdin); print(len([x for x in a if x.get('ipSource')=='99.88.77.66']))" 2>/dev/null || echo "0")
[[ "$ALERT_COUNT" -ge 1 ]] && chk "Brute-force alert generated for 99.88.77.66 ($ALERT_COUNT alert(s))" || \
    warn "No alert yet for 99.88.77.66 — streaming may still be processing"

# ── Summary ───────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo -e "║  Results: ${grn}PASS=$PASS${nc}  ${red}FAIL=$FAIL${nc}  ${yel}WARN=$WARN${nc}$(printf '%*s' $((18-${#PASS}-${#FAIL}-${#WARN})) '')║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
[[ "$FAIL" -gt 0 ]] && exit 1 || exit 0

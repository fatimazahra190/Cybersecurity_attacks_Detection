#!/usr/bin/env bash
# =============================================================================
#  init.sh — CyberSec Lambda — Infrastructure Initialization
#  Run ONCE after "docker compose up -d"
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✅ $*${NC}"; }
warn() { echo -e "${YELLOW}⚠️  $*${NC}"; }
fail() { echo -e "${RED}❌ $*${NC}"; exit 1; }
info() { echo -e "${CYAN}ℹ️  $*${NC}"; }

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   CyberSec Lambda — Infrastructure Initialization       ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# ── Wait helper ───────────────────────────────────────────────────────
wait_for() {
    local name=$1 cmd=$2 retries=${3:-30} delay=${4:-5}
    info "Waiting for $name to be ready…"
    for i in $(seq 1 $retries); do
        if eval "$cmd" &>/dev/null; then
            ok "$name is ready."
            return 0
        fi
        echo "   Attempt $i/$retries — retrying in ${delay}s…"
        sleep "$delay"
    done
    fail "$name did not become ready in time."
}

# ── 1. HADOOP ─────────────────────────────────────────────────────────
echo ""
echo "━━━━ 1. HADOOP ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
wait_for "Hadoop NameNode" \
    "docker exec py-namenode hdfs dfsadmin -safemode get 2>/dev/null | grep -q 'OFF'" \
    40 10

info "Creating HDFS directory structure…"
docker exec py-namenode bash -c "
    hdfs dfs -mkdir -p /data/cybersecurity/logs &&
    hdfs dfs -mkdir -p /data/cybersecurity/batch/ip_reputation &&
    hdfs dfs -mkdir -p /data/cybersecurity/batch/port_scans &&
    hdfs dfs -mkdir -p /data/cybersecurity/batch/attack_patterns &&
    hdfs dfs -mkdir -p /data/cybersecurity/batch/volume_analysis &&
    hdfs dfs -chmod -R 777 /data/cybersecurity
" && ok "HDFS directories created."

# ── 2. KAFKA ──────────────────────────────────────────────────────────
echo ""
echo "━━━━ 2. KAFKA ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
wait_for "Kafka broker" \
    "docker exec py-kafka kafka-topics --bootstrap-server localhost:9092 --list" \
    30 5

info "Creating topic 'cybersecurity-logs' (3 partitions)…"
docker exec py-kafka kafka-topics \
    --bootstrap-server localhost:9092 \
    --create \
    --topic cybersecurity-logs \
    --partitions 3 \
    --replication-factor 1 \
    --config retention.ms=86400000 \
    --if-not-exists && ok "Topic created."

info "Verifying topic:"
docker exec py-kafka kafka-topics \
    --describe \
    --topic cybersecurity-logs \
    --bootstrap-server localhost:9092

# ── 3. CASSANDRA ──────────────────────────────────────────────────────
echo ""
echo "━━━━ 3. CASSANDRA ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
wait_for "Cassandra" \
    "docker exec py-cassandra cqlsh -e 'describe keyspaces'" \
    40 8

info "Creating keyspace..."
docker exec py-cassandra cqlsh -e "CREATE KEYSPACE IF NOT EXISTS cybersecurity WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1};"

info "Creating table..."
docker exec py-cassandra cqlsh -e "CREATE TABLE IF NOT EXISTS cybersecurity.active_threats (ip_source TEXT, bucket_time TIMESTAMP, alert_id UUID, last_seen TIMESTAMP, threat_score INT, attack_types SET<TEXT>, alert_type TEXT, severity TEXT, event_count INT, bytes_total BIGINT, user_agents SET<TEXT>, log_sources SET<TEXT>, PRIMARY KEY ((ip_source), bucket_time, alert_id)) WITH default_time_to_live = 86400 AND CLUSTERING ORDER BY (bucket_time DESC);"
ok "Cassandra schema ready."

# ── 4. HBASE ──────────────────────────────────────────────────────────
echo ""
echo "━━━━ 4. HBASE ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
wait_for "HBase Thrift" \
    "docker exec py-hbase bash -c 'echo > /dev/tcp/localhost/9090' 2>/dev/null" \
    20 5

info "Creating HBase tables…"
docker exec py-hbase hbase shell << 'HBASE_EOF'
create_namespace 'cybersec' if !namespace_exists?('cybersec')
list_tables = list
unless list_tables.include?('ip_reputation')
  create 'ip_reputation', {NAME => 'stats', COMPRESSION => 'NONE'}, {NAME => 'meta', COMPRESSION => 'NONE'}
  puts "Created ip_reputation"
end
unless list_tables.include?('attack_patterns')
  create 'attack_patterns', {NAME => 'pattern'}, {NAME => 'freq'}
  puts "Created attack_patterns"
end
unless list_tables.include?('threat_timeline')
  create 'threat_timeline', {NAME => 'counts'}, {NAME => 'breakdown'}
  puts "Created threat_timeline"
end
list
exit
HBASE_EOF
ok "HBase tables ready."

# ── Summary ───────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   🎉 Initialization complete!                            ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "  Interfaces:"
echo "    Dashboard  : http://localhost:3000"
echo "    API REST   : http://localhost:8080/health"
echo "    HDFS UI    : http://localhost:9870"
echo "    HBase UI   : http://localhost:16010"
echo ""
echo "  Next steps:"
echo "    1. Copy dataset  : ./scripts/load_dataset.sh /path/to/data.csv"
echo "    2. Batch jobs    : ./scripts/run_batch.sh"
echo "    3. Start producer: ./scripts/start_producer.sh"
echo ""

set -euo pipefail

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   Running Batch Layer — 4 Spark Jobs                    ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

run_job() {
    local name=$1 script=$2
    echo "━━━━ $name ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if docker exec py-spark python "/app/batch-layer/$script"; then
        echo "✅ $name completed."
    else
        echo "❌ $name FAILED. Check logs above."
    fi
    echo ""
}

run_job "Job #1 — Top Malicious IPs"       "job_top_malicious_ips.py"
run_job "Job #2 — Port Scan Detection"      "job_port_scan.py"
run_job "Job #3 — Attack Pattern Detection" "job_attack_patterns.py"
run_job "Job #4 — Volume Analysis"          "job_volume_analysis.py"

echo "╔══════════════════════════════════════════════════════════╗"
echo "║   All batch jobs finished.                               ║"
echo "║   API now serves enriched threat profiles.               ║"
echo "╚══════════════════════════════════════════════════════════╝"

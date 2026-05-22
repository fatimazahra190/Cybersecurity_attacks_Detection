Here's a complete verification checklist:

 API Endpoints to test
bash# 1. Full system health — should show all UP
curl http://localhost:8080/health

# 2. Active alerts from speed layer (Cassandra)
curl http://localhost:8080/threats/active

# 3. Global batch stats (HBase) — needs batch jobs done
curl http://localhost:8080/threats/stats

# 4. Timeline (HBase)
curl http://localhost:8080/threats/timeline

# 5. Full Lambda fusion for a known attacker IP
curl http://localhost:8080/threats/ip/42.119.98.70
What confirms success on #5:
json{
  "ip": "42.119.98.70",
  "batchLayer": {
    "reputationScore": 70+,
    "totalHistoricalEvents": 1000+,
    "attackTypesDetected": ["TOOL_DETECTED", "..."]
  },
  "speedLayer": {
    "activeAlerts": 10+,
    "currentThreatScore": 95,
    "recentAttackTypes": ["KNOWN_ATTACK_TOOL"]
  },
  "recommendation": "BLOCK",
  "confidence": 0.90+
}
Both batchLayer and speedLayer populated = Lambda architecture complete.

#  Databases to verify directly
-Cassandra (speed layer):
bashdocker exec py-cassandra cqlsh -e "
SELECT ip_source, alert_type, severity, threat_score 
FROM cybersecurity.active_threats 
LIMIT 5;"
✅ Should show rows with CRITICAL alerts.

-HBase (batch layer):
bashdocker exec py-hbase /hbase/bin/hbase shell <<'EOF'
count 'ip_reputation'
count 'attack_patterns'
count 'threat_timeline'
EOF
✅ Should show non-zero counts after batch jobs.

-HDFS (raw + parquet data):
bashdocker exec py-namenode hdfs dfs -ls /data/cybersecurity/logs/
✅ Should show .parquet files.


#  Web Interfaces
URLWhat you should seehttp://localhost:3000Dashboard with chartshttp://localhost:9870HDFS file browser — shows parquet files in /data/http://localhost:16010HBase Master UI — shows 3 tables, RegionServer online

Dashboard at http://localhost:3000
A fully working dashboard should show:
Charts/widgets expected:

Active threats count (number updating in near real-time)
Threat severity breakdown — pie or bar chart (CRITICAL / HIGH)
Top attacker IPs — bar chart (42.119.98.70 should be #1)
Attack types distribution — KNOWN_ATTACK_TOOL, LFI, SQLI, BRUTE_FORCE
Timeline/trend chart — alerts over the last hour
Recent alerts table — scrollable list with IP, type, score, timestamp

What confirms the dashboard is live:

Numbers change every 30-60 seconds as new Kafka messages are processed
The alert table shows timestamps from the last few minutes
IP 42.119.98.70 appears prominently as top threat


# Final success criteria summary
Check                   Command/URL                                    Expected  
All services            healthycurl localhost:8080/health"             status":"UP"
Speed layer working     curl localhost:8080/threats/                   activeJSON array of alerts
Batch layer working     curl localhost:8080/threats/stats              total_ips_analyzed > 0 
Lambda fusion           curl localhost:8080/threats/ip/42.119.98.70    Both layers populated
Cassandra has data      cqlsh query                                    Rows returned
HBase has data          hbase count                                    > 0 rows
HDFS has parquet        hdfs dfs -ls                                   .parquet files listed
Dashboard loads         localhost:3000                                 Charts with live data
Kafka flowing           docker logs py-producer                        Sent: X,000 msg/s
Streaming detecting     docker logs py-streaming                       Batch N — X alerts
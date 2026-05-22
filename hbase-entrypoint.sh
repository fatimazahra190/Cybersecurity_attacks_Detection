#!/bin/bash
set -e

ZK_HOST="${HBASE_CONF_hbase_zookeeper_quorum:-zookeeper}"
ZK_PORT="2181"
NAMENODE_HOST="namenode"
NAMENODE_PORT="9000"

# ── 1. Attendre ZooKeeper ─────────────────────────────────────────
echo " Attente ZooKeeper ${ZK_HOST}:${ZK_PORT}..."
until nc -z "$ZK_HOST" "$ZK_PORT" 2>/dev/null; do
  echo "   ZooKeeper pas prêt, attente 3s..."
  sleep 3
done
echo "✅ ZooKeeper prêt"

# ── 2. Attendre HDFS ──────────────────────────────────────────────
echo " Attente HDFS ${NAMENODE_HOST}:${NAMENODE_PORT}..."
until nc -z "$NAMENODE_HOST" "$NAMENODE_PORT" 2>/dev/null; do
  echo "   HDFS pas prêt, attente 3s..."
  sleep 3
done
echo "✅ HDFS prêt"
sleep 10  # Laisser le namenode sortir du safe mode

# ── 3. Générer hbase-site.xml avec les bons timeouts ─────────────
echo " Configuration hbase-site.xml..."
cat > /hbase/conf/hbase-site.xml << EOF
<?xml version="1.0"?>
<configuration>

  <property>
    <name>hbase.rootdir</name>
    <value>hdfs://${NAMENODE_HOST}:${NAMENODE_PORT}/hbase</value>
  </property>

  <property>
    <name>hbase.cluster.distributed</name>
    <value>false</value>
  </property>

  <property>
    <name>hbase.zookeeper.quorum</name>
    <value>${ZK_HOST}</value>
  </property>

  <property>
    <name>hbase.zookeeper.property.clientPort</name>
    <value>${ZK_PORT}</value>
  </property>

  <!-- Fix ZooKeeper session expiry -->
  <property>
    <name>zookeeper.session.timeout</name>
    <value>120000</value>
  </property>

  <property>
    <name>zookeeper.recovery.retry</name>
    <value>10</value>
  </property>

  <property>
    <name>hbase.zookeeper.recoverable.waittime</name>
    <value>30000</value>
  </property>

  <!-- Fix hostname resolution dans Docker -->
  <property>
    <name>hbase.regionserver.hostname</name>
    <value>hbase</value>
  </property>

  <property>
    <name>hbase.master.hostname</name>
    <value>hbase</value>
  </property>

  <property>
    <name>hbase.master.port</name>
    <value>16000</value>
  </property>

  <property>
    <name>hbase.master.info.port</name>
    <value>16010</value>
  </property>

  <property>
    <name>hbase.regionserver.port</name>
    <value>16020</value>
  </property>

  <property>
    <name>h
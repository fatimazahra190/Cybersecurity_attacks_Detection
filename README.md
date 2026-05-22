# 🛡️ CyberSec Threat Detection System — Architecture Lambda (Python)

Système complet de détection de menaces réseau basé sur l'**architecture Lambda**,
entièrement codé en **Python 3.11** et orchestré via Docker Compose.

---

##  Meilleur outil sur Windows 11

> **Recommandation : WSL 2 (Ubuntu 22.04)**

| Outil      | Verdict | Raison |
|------------|---------|--------|
| **WSL 2**  | ✅ Recommandé | Shell Linux natif, Docker Desktop intégré, performances optimales |
| Git Bash   | ⚠️ Partiel   | Pas de support complet des scripts bash avancés (`nc`, `cqlsh`) |
| PowerShell | ❌ Non recommandé | Syntaxe incompatible avec les scripts `.sh` |
| CMD        | ❌ Non recommandé | Ne supporte pas les scripts bash |

### Installation WSL 2 
```powershell
# Dans PowerShell (Administrateur)
wsl --install -d Ubuntu-22.04
wsl --set-default-version 2
```
Puis installer **Docker Desktop** → Settings → Use WSL 2 backend ✅

---

##  Architecture

```
CSV/Logs ──→ HDFS ──→ Spark Batch (Python) ──→ HBase ──────────────┐
                                                                     ▼
Logs live ──→ Kafka ──→ Spark Streaming (Python) ──→ Cassandra ──→ API Flask ──→ Dashboard HTML
                                                                     ▲
                                                       Fusion batch + speed
```

| Couche   | Technologies | Rôle |
|----------|-------------|------|
| Batch    | HDFS 3.2 + PySpark 3.4 + HBase 2.x | Analyses historiques |
| Speed    | Kafka 3.4 + PySpark Streaming 3.4 + Cassandra 4.1 | Détection temps réel |
| Serving  | Flask 3.0 + HappyBase + Cassandra-driver | API REST + fusion |
| Dashboard| HTML/CSS/JS + Chart.js 4 + Nginx | Visualisation |

---

## Prérequis

| Logiciel | Version | Installation |
|----------|---------|-------------|
| WSL 2 + Ubuntu 22.04 | — | `wsl --install -d Ubuntu-22.04` |
| Docker Desktop | 24+ | https://docs.docker.com/desktop/windows/ |
| Git | — | `sudo apt install git` (dans WSL) |
| Python 3.x (optionnel) | 3.9+ | Pour tester l'API depuis l'hôte |

> **RAM minimum : 12 Go allouée à WSL/Docker** (16 Go recommandé)
> Docker Desktop → Settings → Resources → Memory : 10 GB minimum

---

## Guide de démarrage complet (étape par étape)

### ──────── ÉTAPE 0 : Cloner et préparer  ────────

```bash
# Dans WSL Ubuntu
cd ~
git clone <nom_repo> cybersec-lambda
cd cybersec-lambda

# Copier le fichier d'environnement
cp .env.local .env

# Rendre les scripts exécutables
chmod +x init.sh demo.sh scripts/*.sh

# Créer le dossier data
mkdir -p data

# Copier votre dataset CSV dans le dossier data
cp /mnt/c/Users/VotreNom/Downloads/cybersecurity_threat_detection_logs.csv data/
```

---

### ──────── ÉTAPE 1 : Démarrer l'infrastructure (À CHAQUE LANCEMENT) ────────

```bash
# Démarrer tous les conteneurs (environ 3-5 min au premier lancement)
docker compose up -d

# Surveiller le démarrage
docker compose ps
```

Attendez que tous ces services soient **healthy** :
```
zookeeper   → healthy
kafka       → healthy
namenode    → healthy
cassandra   → healthy
hbase       → healthy (peut prendre 3-4 min)
api         → healthy
```

Pour surveiller en temps réel :
```bash
watch -n 3 'docker compose ps'
```

---

### ──────── ÉTAPE 2 : Initialiser les bases de données  ────────

```bash
# Lance la création des topics Kafka, tables Cassandra, tables HBase, répertoires HDFS
./init.sh
```


---

### ──────── ÉTAPE 3 : Charger le dataset CSV (UNE SEULE FOIS) ────────

```bash
# Charge le CSV dans HDFS et le convertit en Parquet partitionné par date
./scripts/load_dataset.sh data/cybersecurity_threat_detection_logs.csv
```

> Vérification : `docker exec py-namenode hdfs dfs -ls /data/cybersecurity/logs/`

---

### ──────── ÉTAPE 4 : Lancer les jobs batch (UNE SEULE FOIS par cycle) ────────

```bash
# Exécute les 4 analyses Spark et peuple HBase
./scripts/run_batch.sh
```

Jobs exécutés dans l'ordre :
- **Job #1** : Top 10 IPs malveillantes → HBase `ip_reputation`
- **Job #2** : Détection port scanning → HBase `attack_patterns`
- **Job #3** : Détection SQLi/XSS/LFI/tools → HBase `attack_patterns`
- **Job #4** : Analyse volumétrique + timeline → HBase `threat_timeline`


---

### ──────── ÉTAPE 5 : Démarrer le streaming temps réel (À CHAQUE LANCEMENT) ────────

Le streaming Spark tourne déjà dans le conteneur `streaming`.
Vérifier qu'il est actif :
```bash
docker logs -f py-streaming
```

Vous devriez voir : `✅ 3 detectors active. Waiting for Kafka messages…`

---

### ──────── ÉTAPE 6 : Lancer le producteur Kafka (À CHAQUE LANCEMENT) ────────

```bash
# Option A : Producteur en continu depuis le CSV (boucle infinie)
docker exec -d py-producer python /app/kafka_producer.py \
    --input /app/data/cybersecurity_threat_detection_logs.csv \
    --rate 10 --loop

# Option B : Scénario de démo rapide (3 attaques pré-définies)
docker exec py-producer python /app/kafka_producer.py --demo

# Surveiller les logs du producteur
docker logs -f py-producer
```

---

### ──────── ÉTAPE 7 : Accéder aux interfaces ────────

| Interface    | URL                              | Description |
|-------------|----------------------------------|-------------|
| Dashboard | http://localhost:3000             | Tableau de bord principal |
| API REST  | http://localhost:8080/health      | Health check |
| HDFS UI   | http://localhost:9870             | Explorateur de fichiers HDFS |
| HBase UI  | http://localhost:16010            | Interface HBase |
| Alertes   | http://localhost:8080/threats/active | Liste des alertes JSON |

---

### ──────── ÉTAPE 8 : Lancer la démo end-to-end ────────

```bash
# Injecte 3 scénarios d'attaque et vérifie les alertes générées
./demo.sh
```

Scénarios injectés :
- 8 connexions bloquées → détection **BRUTE_FORCE** par l'IP `10.10.10.1`
- User-agent `sqlmap/1.7.8` → détection **KNOWN_ATTACK_TOOL** par `10.20.30.40`
- 15 Mo transférés → détection **VOLUME_ANOMALY** par `172.16.0.5`

---

##  Tests unitaires

```bash
# Lancer tous les tests (dans le conteneur Spark)
docker exec py-spark python -m pytest /app/batch-layer/test_batch.py -v

# Tests spécifiques
docker exec py-spark python -m pytest /app/batch-layer/test_batch.py::TestBruteForceLogic -v
docker exec py-spark python -m pytest /app/batch-layer/test_batch.py::TestThreatFusionLogic -v
```

---

##  Checklist de vérification automatique

```bash
# Lance une série de 30+ vérifications automatiques
./scripts/checklist.sh
```

---

## Endpoints API REST

| Méthode | Endpoint              | Description                         | SLA    |
|---------|-----------------------|-------------------------------------|--------|
| GET     | `/health`             | Statut API + HBase + Cassandra      | <50ms  |
| GET     | `/threats/ip/{ip}`    | Profil complet d'une IP (batch+speed)| <200ms |
| GET     | `/threats/active`     | Toutes les alertes actives (24h)    | <300ms |
| GET     | `/threats/stats`      | Statistiques globales batch         | <500ms |
| GET     | `/threats/timeline`   | Évolution temporelle horaire        | <500ms |

### Exemple de réponse `/threats/ip/10.10.10.1` :
```json
{
  "ip": "10.10.10.1",
  "batchLayer": {
    "reputationScore": 87,
    "totalHistoricalEvents": 1243,
    "attackTypesDetected": ["BRUTE_FORCE", "SQLI"],
    "lastBatchUpdate": "2023-10-14T23:00:00"
  },
  "speedLayer": {
    "activeAlerts": 3,
    "lastSeen": "2023-10-15T14:23:45Z",
    "currentThreatScore": 92,
    "recentAttackTypes": ["BRUTE_FORCE"],
    "bytesLastHour": 52428800
  },
  "recommendation": "BLOCK",
  "confidence": 0.94
}
```

---

## Détections implémentées

| Type            | Déclencheur                                    | Score   | Couche      |
|-----------------|------------------------------------------------|---------|-------------|
| Brute-Force     | 5+ `action=blocked` en 1 minute               | 70–100  | Speed       |
| Port Scan       | 20+ dest_ip TCP distincts en 5 min            | 60+     | Batch+Speed |
| SQLi/XSS/LFI   | Pattern regex dans `request_path`             | 70–85   | Batch+Speed |
| Outil malveillant| sqlmap/nikto/nmap… dans `user_agent`         | 95      | Batch+Speed |
| Anomalie volume | >10 MB en 10 secondes depuis même IP          | 80+     | Speed       |

---

## 📂 Structure du projet

```
cybersec-lambda/
├── docker-compose.yml          # Infrastructure complète
├── Dockerfile.spark            # Image Python+Spark partagée
├── requirements.spark.txt      # Dépendances Spark/batch/streaming
├── init.sh                     # Initialisation (une seule fois)
├── demo.sh                     # Démo end-to-end
├── .env.local                  # Variables d'environnement
│
├── batch-layer/
│   ├── spark_config.py         # Configuration SparkSession
│   ├── hbase_writer.py         # Utilitaire écriture HBase
│   ├── convert_to_parquet.py   # Conversion CSV → Parquet HDFS
│   ├── job_top_malicious_ips.py
│   ├── job_port_scan.py
│   ├── job_attack_patterns.py
│   ├── job_volume_analysis.py
│   ├── run_all_jobs.py
│   └── test_batch.py           # Tests unitaires
│
├── speed-layer/
│   ├── streaming_app.py        # Spark Streaming (3 détecteurs)
│   ├── cassandra_writer.py     # Utilitaire écriture Cassandra
│   ├── Dockerfile.producer
│   └── producer/
│       ├── kafka_producer.py
│       └── requirements.txt
│
├── serving-layer/
│   ├── app.py                  # Flask REST API
│   ├── hbase_service.py        # Lecture HBase
│   ├── cassandra_service.py    # Lecture Cassandra
│   ├── threat_fusion.py        # Logique de fusion batch+speed
│   ├── requirements.txt
│   └── Dockerfile
│
├── dashboard/
│   ├── html/index.html         # Dashboard Chart.js
│   └── nginx.conf
│
├── scripts/
│   ├── load_dataset.sh
│   ├── run_batch.sh
│   ├── start_producer.sh
│   └── checklist.sh
│
└── data/                       # CSV à placer ici (ignoré par git)
```

---

## Commandes utiles

```bash
# Voir les logs d'un service
docker logs -f py-streaming       # Spark streaming
docker logs -f py-api             # API Flask
docker logs -f py-producer        # Kafka producer

# Arrêter tout
docker compose down

# Arrêter et supprimer les volumes (réinitialisation complète)
docker compose down -v

# Inspecter Cassandra manuellement
docker exec -it cassandra cqlsh
> SELECT * FROM cybersecurity.active_threats LIMIT 10;

# Inspecter HDFS
docker exec namenode hdfs dfs -ls -R /data/cybersecurity/

# Vérifier les topics Kafka
docker exec kafka kafka-console-consumer \
    --bootstrap-server localhost:9092 \
    --topic cybersecurity-logs \
    --from-beginning --max-messages 5
```

---

## Résolution des problèmes courants

| Problème | Cause | Solution |
|----------|-------|----------|
| `namenode` reste en safemode | Pas assez de DataNodes | `docker exec namenode hdfs dfsadmin -safemode leave` |
| HBase ne démarre pas | Dépend de HDFS | Attendre que namenode soit healthy puis `docker restart hbase` |
| Cassandra `Connection refused` | Démarrage lent | Attendre 2 min supplémentaires, retry |
| Spark `OutOfMemory` | Dataset trop grand | Réduire le CSV à 10% : `head -n 10000 data/full.csv > data/sample.csv` |
| API retourne `503` | HBase ou Cassandra DOWN | Vérifier `docker compose ps` et relancer les services DOWN |
| Dashboard ne charge pas | API non accessible | Vérifier CORS et que l'API tourne sur le port 8080 |
| `kafka-topics: not found` | Conteneur Kafka pas prêt | Attendre `kafka` → healthy puis réessayer |

---

##  Logique de recommandation

| Score batch | Alertes speed actives | Recommandation |
|-------------|----------------------|----------------|
| > 80        | ≥ 1                  | **BLOCK** — Blocage immédiat |
| ≥ 50        | N/A                  | **MONITOR** — Surveillance renforcée |
| < 50        | > 0                  | **MONITOR** — Alerte récente sans historique |
| < 50        | 0                    | **ALLOW** — Autoriser avec log |

---

##  Sécurité (hors périmètre projet)

- Authentification API : non implémentée (Bearer JWT recommandé en production)
- Chiffrement at rest : désactivé en dev
- Isolation réseau : tous les services dans le réseau `cybersec-net` (172.20.0.0/16)

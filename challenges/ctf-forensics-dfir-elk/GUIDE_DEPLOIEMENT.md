# 🛠️ Guide complet : CTFd + Plugin Docker + Challenge DFIR ELK

## Architecture finale

```
┌─────────────────────────────────────────────────────────────┐
│                    Serveur (Tailscale : 100.X.X.X)          │
│                                                              │
│  ┌──────────────┐    ┌──────────────────────────────────┐   │
│  │    CTFd      │    │   Instances challenge (Docker)    │   │
│  │  :8000       │    │                                   │   │
│  │              │───▶│  Équipe A → port 32100            │   │
│  │ Plugin       │    │  Équipe B → port 32101            │   │
│  │ containers   │    │  Équipe C → port 32102            │   │
│  └──────────────┘    │  (chaque instance = ELK isolé)    │   │
│                      └──────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
         │                        │
         ▼                        ▼
   Équipes accèdent         Équipes accèdent
   CTFd via Tailscale       leur Kibana via Tailscale
   100.X.X.X:8000           100.X.X.X:<port_assigné>
```

---

## PARTIE 1 — Build de l'image Docker du challenge

### 1.1 Structure du projet

```
ctf-forensics-dfir-elk/
├── README.md                  ← Présentation du challenge
├── Dockerfile                 ← Image du challenge (ELK tout-en-un)
├── GUIDE_DEPLOIEMENT.md       ← Vous êtes ici
├── supervisord.conf           ← Orchestration des services ELK
├── pipeline/
│   └── logstash.conf          ← Pipeline d'ingestion des logs
├── init/
│   ├── inject_logs.py         ← Injection des logs dans Elasticsearch
│   └── import_kibana.sh       ← Import des index patterns Kibana
└── docs/
    └── USER_GUIDE.md          ← Guide joueur
```

### 1.2 Dockerfile du challenge (image self-contained)

Le challenge est une image Docker **tout-en-un** qui embarque ES + Kibana + Logstash
dans un seul conteneur via supervisord.

```dockerfile
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV ES_VERSION=8.11.0

# ── Dépendances système ──────────────────────────────────────
RUN apt-get update && apt-get install -y \
    wget curl gnupg supervisor default-jdk \
    && rm -rf /var/lib/apt/lists/*

# ── Clé GPG Elastic ─────────────────────────────────────────
RUN wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch \
    | gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] \
    https://artifacts.elastic.co/packages/8.x/apt stable main" \
    > /etc/apt/sources.list.d/elastic-8.x.list

# ── Installation ES + Kibana + Logstash ─────────────────────
RUN apt-get update && apt-get install -y \
    elasticsearch=${ES_VERSION} \
    kibana=${ES_VERSION} \
    logstash \
    && rm -rf /var/lib/apt/lists/*

# ── Config Elasticsearch ─────────────────────────────────────
RUN echo "network.host: 0.0.0.0" >> /etc/elasticsearch/elasticsearch.yml \
    && echo "discovery.type: single-node" >> /etc/elasticsearch/elasticsearch.yml \
    && echo "xpack.security.enabled: false" >> /etc/elasticsearch/elasticsearch.yml \
    && echo "xpack.security.http.ssl.enabled: false" >> /etc/elasticsearch/elasticsearch.yml

# ── Config Kibana ────────────────────────────────────────────
RUN echo 'server.host: "0.0.0.0"' >> /etc/kibana/kibana.yml \
    && echo 'elasticsearch.hosts: ["http://localhost:9200"]' >> /etc/kibana/kibana.yml \
    && echo 'xpack.security.enabled: false' >> /etc/kibana/kibana.yml \
    && echo 'telemetry.enabled: false' >> /etc/kibana/kibana.yml

# ── Logstash pipeline et logs ────────────────────────────────
COPY pipeline/logstash.conf /etc/logstash/conf.d/logstash.conf
COPY logs/ /opt/ctf-logs/

# ── Supervisord ──────────────────────────────────────────────
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# ── Script d'init Kibana (index pattern) ────────────────────
COPY init/import_kibana.sh /opt/import_kibana.sh
RUN chmod +x /opt/import_kibana.sh

EXPOSE 5601

CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
```

### 1.3 supervisord.conf

```ini
[supervisord]
nodaemon=true
logfile=/var/log/supervisord.log

[program:elasticsearch]
command=/usr/share/elasticsearch/bin/elasticsearch
user=elasticsearch
environment=ES_JAVA_OPTS="-Xms512m -Xmx512m"
stdout_logfile=/var/log/elasticsearch.log
stderr_logfile=/var/log/elasticsearch.log
autorestart=true
priority=10

[program:kibana]
command=/usr/share/kibana/bin/kibana
user=kibana
stdout_logfile=/var/log/kibana.log
stderr_logfile=/var/log/kibana.log
autorestart=true
priority=20

[program:logstash]
command=/usr/share/logstash/bin/logstash -f /etc/logstash/conf.d/logstash.conf
user=logstash
environment=LS_JAVA_OPTS="-Xms256m -Xmx256m"
stdout_logfile=/var/log/logstash.log
stderr_logfile=/var/log/logstash.log
autorestart=false
startsecs=30
priority=30

[program:kibana-init]
command=/opt/import_kibana.sh
stdout_logfile=/var/log/kibana-init.log
autorestart=false
startsecs=120
priority=40
```

### 1.4 logstash.conf adapté (chemin local)

```ruby
input {
  file {
    path => "/opt/ctf-logs/*.json"
    start_position => "beginning"
    sincedb_path => "/dev/null"
    codec => json
    mode => "read"
  }
}

filter {
  date {
    match => ["@timestamp", "ISO8601"]
    target => "@timestamp"
  }
  mutate {
    add_field => {
      "environment"  => "corp.local"
      "ctf_scenario" => "DFIR-Incident-2024-03-15"
    }
  }
}

output {
  elasticsearch {
    hosts => ["http://localhost:9200"]
    index => "dfir-incident-%{+YYYY.MM.dd}"
  }
}
```

### 1.5 Build et tag de l'image

```bash
# Se placer dans le répertoire ctf-elk/
cd ctf-elk/

# Build de l'image (tag local, pas besoin de registry externe !)
docker build -t ctf-dfir-elk:latest .

# Vérifier que l'image est bien présente
docker images | grep ctf-dfir-elk
```

> **Note sur `<YOUR_REGISTRY>`** : avec le plugin CTFd Docker local, tu n'as
> **pas besoin** de registry externe (DockerHub, GitHub Container Registry...).
> Le plugin utilise directement le daemon Docker local du serveur.
> L'image doit juste être présente localement sur le serveur avec `docker images`.

---

## PARTIE 2 — Installation de CTFd

### 2.1 Cloner CTFd

```bash
cd /opt
git clone https://github.com/CTFd/CTFd.git
cd CTFd
```

### 2.2 docker-compose.yml CTFd (adapté pour le plugin)

```yaml
# /opt/CTFd/docker-compose.yml
version: "3"

services:
  ctfd:
    build: .
    user: root
    restart: always
    ports:
      - "8000:8000"
    environment:
      - UPLOAD_FOLDER=/var/uploads
      - DATABASE_URL=mysql+pymysql://ctfd:ctfd@db/ctfd
      - REDIS_URL=redis://cache:6379
      - WORKERS=1
      - LOG_FOLDER=/var/log/CTFd
      - ACCESS_LOG=-
      - ERROR_LOG=-
      - REVERSE_PROXY=false
    volumes:
      - .data/CTFd/logs:/var/log/CTFd
      - .data/CTFd/uploads:/var/uploads
      - .:/opt/CTFd:ro
      # ⚠️ CRITIQUE : expose le socket Docker à CTFd pour le plugin
      - /var/run/docker.sock:/var/run/docker.sock
    depends_on:
      - db
    networks:
      default:

  db:
    image: mariadb:10.11
    restart: always
    environment:
      - MYSQL_ROOT_PASSWORD=ctfd
      - MYSQL_USER=ctfd
      - MYSQL_PASSWORD=ctfd
      - MYSQL_DATABASE=ctfd
    volumes:
      - .data/mysql:/var/lib/mysql
    networks:
      default:

  cache:
    image: redis:4
    restart: always
    volumes:
      - .data/redis:/data
    networks:
      default:

networks:
  default:
```

### 2.3 Lancer CTFd

```bash
cd /opt/CTFd
docker-compose up -d
# CTFd disponible sur http://100.X.X.X:8000
```

---

## PARTIE 3 — Installation du plugin CTFd Docker Containers

Le plugin recommandé est **CTFdDockerContainersPlugin** (Bigyls),
fork maintenu de andyjsmith/CTFd-Docker-Plugin.

### 3.1 Installation du plugin

```bash
cd /opt/CTFd/CTFd/plugins

# Cloner le plugin (doit s'appeler exactement "containers")
git clone https://github.com/Bigyls/CTFdDockerContainersPlugin.git containers

# Installer les dépendances Python du plugin
cd containers
pip install -r requirements.txt
```

### 3.2 Redémarrer CTFd

```bash
cd /opt/CTFd
docker-compose restart ctfd
```

### 3.3 Configurer le plugin dans l'interface CTFd

1. Ouvrir **http://100.X.X.X:8000** → Se connecter en admin
2. Aller dans **Admin Panel** → barre de navigation → **Plugins** → **Containers**
3. Cliquer sur **Settings**
4. Remplir :

| Champ | Valeur |
|-------|--------|
| **Connection Type** | `unix_socket` |
| **Connection String** | `/var/run/docker.sock` |
| **Base URL** | `http://100.X.X.X` ← **ton IP Tailscale** |
| **Container Timeout** | `7200` (2h) |
| **Max Containers** | `20` (ou nombre d'équipes) |

5. Cliquer **Save** → le plugin doit afficher une icône verte ✅

---

## PARTIE 4 — Créer le challenge dans CTFd

### 4.1 Créer le challenge

1. **Admin Panel** → **Challenges** → **+ New Challenge**
2. Remplir :

| Champ | Valeur |
|-------|--------|
| **Name** | `DFIR – Incident CORP.LOCAL` |
| **Category** | `Forensics` |
| **Type** | `container` ← type ajouté par le plugin |
| **Value** | `500` (total des points, ou gérer flag par flag) |
| **Image** | `ctf-dfir-elk:latest` |
| **Port** | `5601` |
| **Connect Type** | `http` |

3. Dans la description, mettre le contexte (voir ci-dessous)
4. **Save**

### 4.2 Description du challenge pour les joueurs

```markdown
## 🔍 DFIR – Incident CORP.LOCAL

Un incident de sécurité s'est produit sur le domaine **CORP.LOCAL**.
Vous avez accès à une instance **Kibana** contenant les logs Windows
des trois machines de l'infrastructure.

Votre mission : analyser les logs et reconstituer la chaîne d'attaque.

**Infrastructure :**
- `WIN-ACCT01` — Poste utilisateur (192.168.10.45)
- `APP-SRV01` — Serveur applicatif (192.168.10.52)
- `DC01` — Domain Controller (192.168.10.10)

**Cliquez sur "Start Instance" pour lancer votre environnement Kibana.**
L'instance peut prendre 2-3 minutes à démarrer.

> Accès : `http://100.X.X.X:<port_assigné>` (visible après démarrage)
```

### 4.3 Créer les 10 flags dans CTFd

Créer **10 challenges séparés** (ou 10 flags sur le même challenge selon ta config CTFd).
Le plus propre est de faire **un challenge par flag** dans la même catégorie :

| Challenge | Flag | Points |
|-----------|------|--------|
| FLAG 1 – IP du C2 | `FLAG{185.243.115.23}` | 50 |
| FLAG 2 – Commande PowerShell encodée | `FLAG{SQBFAFgA...}` | 100 |
| FLAG 3 – Script téléchargé | `FLAG{update.ps1}` | 100 |
| FLAG 4 – SHA256 outil énumération | `FLAG{9f86d08...}` | 150 |
| FLAG 5 – Technique MITRE dump LSASS | `FLAG{T1003.001}` | 150 |
| FLAG 6 – Compte pivot vers APP-SRV01 | `FLAG{svc_backup}` | 150 |
| FLAG 7 – Heure premier RDP APP-SRV01 | `FLAG{09:48:12}` | 200 |
| FLAG 8 – Type auth Kerberos DC | `FLAG{Kerberos_TGS}` | 250 |
| FLAG 9 – SID ajouté groupe privilégié | `FLAG{S-1-5-21-...}` | 300 |
| FLAG 10 – Compte persistant + SPN | `FLAG{svc_update$}` | 400 |

> Pour FLAG 4 : les joueurs voient `SharpHound.exe` dans les logs
> et doivent **chercher eux-mêmes le SHA256 sur VirusTotal / GitHub**.
> Le hash n'apparaît **pas** dans les logs du challenge.

---

## PARTIE 5 — Isolation des instances par équipe

Le plugin gère **automatiquement** l'isolation :

- Chaque équipe clique **"Start Instance"** → le plugin lance un nouveau conteneur Docker
- Chaque conteneur a un **port aléatoire** assigné (ex: 32100, 32101...)
- Les conteneurs sont sur des réseaux Docker **isolés** (pas de communication inter-équipes)
- Le joueur voit son URL : `http://100.X.X.X:32100` dans l'interface CTFd

Pour vérifier les instances actives (admin) :
→ **Admin Panel** → **Plugins** → **Containers** → liste des conteneurs actifs

---

## PARTIE 6 — Accès Tailscale

Les joueurs se connectent à Tailscale et accèdent :

- **CTFd** : `http://100.X.X.X:8000`
- **Leur Kibana** : `http://100.X.X.X:<port_assigné>` (affiché par CTFd après "Start")

Si tu veux exposer uniquement via Tailscale (pas d'accès public) :

```bash
# Vérifier l'IP Tailscale du serveur
tailscale ip -4
# → 100.X.X.X

# S'assurer que les ports 8000 et 32000-33000 sont autorisés dans le firewall
ufw allow from 100.64.0.0/10 to any port 8000
ufw allow from 100.64.0.0/10 to any port 32000:33000/tcp
```

---

## PARTIE 7 — Commandes utiles

```bash
# Voir toutes les instances en cours
docker ps | grep ctf-dfir-elk

# Logs d'une instance
docker logs <container_id>

# Tuer une instance manuellement
docker stop <container_id>

# Vérifier l'espace disque (chaque instance = ~2GB)
df -h

# Voir l'index ES d'une instance (depuis le serveur)
curl http://localhost:<port_es>/dfir-incident-*/_count
```

---

## PARTIE 8 — Ressources mémoire estimées

| Composant | RAM par instance |
|-----------|-----------------|
| Elasticsearch | ~512 MB |
| Kibana | ~512 MB |
| Logstash | ~256 MB |
| **Total/équipe** | **~1.3 GB** |

Pour 10 équipes simultanées → **~13 GB RAM** minimum sur le serveur.

---

## Checklist de déploiement

- [ ] Image `ctf-dfir-elk:latest` buildée sur le serveur
- [ ] CTFd lancé (`docker-compose up -d`)
- [ ] Plugin `containers` installé dans `/opt/CTFd/CTFd/plugins/containers`
- [ ] Plugin configuré avec socket Docker + IP Tailscale
- [ ] Challenge créé avec image `ctf-dfir-elk:latest` port `5601`
- [ ] 10 flags créés dans CTFd
- [ ] Test : lancer une instance manuellement et vérifier Kibana
- [ ] Test accès Tailscale : `http://100.X.X.X:8000`

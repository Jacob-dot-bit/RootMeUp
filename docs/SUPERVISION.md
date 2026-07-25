# Supervision — RootMeUp

Supervision de la santé du serveur CTFd (métriques temps réel) + **alerting** vers
Discord. Objectif : anticiper les incidents (le crash du T2 était dû à un **disque
plein**) plutôt que de les subir.

## Architecture

```
   VM Grafana (Tailscale 100.84.158.83)        VM CTF (100.118.132.76)
   ┌─────────────────────────────┐             ┌──────────────────────────┐
   │ Grafana        :3000         │             │ node_exporter   :9100    │
   │ Prometheus     :9090  ──────────scrape────►│ (métriques système)      │
   │  └─ règles d'alerte          │             │ CTFd (Apache :80)        │
   │        └─► Discord (webhook) │             └──────────────────────────┘
   └─────────────────────────────┘
```

- **node_exporter** (sur la VM CTF) : expose CPU / RAM / disque / réseau.
- **Prometheus** (VM Grafana) : collecte (scrape) les métriques toutes les 15 s.
- **Grafana** (VM Grafana) : dashboards + moteur d'alerting.
- **Discord** : réception des alertes (webhook — **secret, non committé**, voir §Sécurité).

La VM Grafana est une VM Debian dédiée sur le Proxmox (`vmbr1`, Internet via NAT de
l'hôte, accès distant par Tailscale).

## Installation / reproduction

### 1. Sur la VM CTF — agent de métriques
```bash
sudo apt install -y prometheus-node-exporter
sudo systemctl enable --now prometheus-node-exporter   # écoute sur :9100
```

### 2. Sur la VM Grafana — Grafana + Prometheus
```bash
# Grafana (dépôt officiel)
sudo apt install -y apt-transport-https software-properties-common wget
sudo mkdir -p /etc/apt/keyrings/
wget -qO- https://apt.grafana.com/gpg.key | sudo gpg --dearmor | sudo tee /etc/apt/keyrings/grafana.gpg >/dev/null
echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
sudo apt update && sudo apt install -y grafana prometheus
sudo systemctl enable --now grafana-server prometheus
```

### 3. Prometheus — scraper la VM CTF
Ajouter dans `/etc/prometheus/prometheus.yml` :
```yaml
scrape_configs:
  - job_name: 'ctf-vm'
    static_configs:
      - targets: ['100.118.132.76:9100']
```
```bash
sudo systemctl restart prometheus
# vérifier la cible UP : http://<grafana>:9090/targets
```

### 4. Grafana — source de données + dashboard (provisionnés)
`/etc/grafana/provisioning/datasources/prometheus.yml` :
```yaml
apiVersion: 1
datasources:
  - name: Prometheus
    uid: prometheus
    type: prometheus
    access: proxy
    url: http://localhost:9090
    isDefault: true
```
Dashboard **« Node Exporter Full » (ID 1860)** provisionné dans
`/var/lib/grafana/dashboards/` (télécharger depuis `grafana.com/api/dashboards/1860`,
remplacer `${DS_PROMETHEUS}` par `prometheus`).

### 5. Alerting Discord
- **Point de contact** `Discord` + politique par défaut →
  `/etc/grafana/provisioning/alerting/discord.yaml` (contient le webhook — **jamais committé**).
- **Règles** (`/etc/grafana/provisioning/alerting/rules.yaml`), toutes routées vers Discord :

| Règle | Condition | Sévérité |
|---|---|---|
| Serveur CTFd injoignable | `up{job="ctf-vm"} == 0` pendant 1 min | critique |
| Disque presque plein | filesystem `ext4/xfs` de la VM CTF > 85 % pendant 5 min | warning |
| RAM haute | mémoire utilisée de la VM CTF > 90 % pendant 5 min | warning |

## Accès

- **Grafana** : `http://100.84.158.83:3000` (via Tailscale). Changer le mot de passe admin par défaut.
- **Prometheus** : `http://100.84.158.83:9090`.
- Dashboard : *Dashboards → Node Exporter Full*, sélectionner le job `ctf-vm`.

## Sécurité

- Le **webhook Discord** est un secret : il n'existe **que** dans
  `/etc/grafana/provisioning/alerting/discord.yaml` sur la VM Grafana, **jamais dans git**.
- Grafana/Prometheus ne sont pas exposés sur Internet (accès uniquement via Tailscale).
- Changer les identifiants Grafana par défaut (`admin`/`admin`).

## Évolutions possibles

- **Disponibilité HTTP** de CTFd (temps de réponse, code) → `prometheus-blackbox-exporter`.
- **Métriques des conteneurs** de challenges (RAM/CPU par instance) → `cAdvisor`.
- **Statistiques CTF** (équipes, résolutions, flags soumis) → source de données MySQL sur la base `ctfd`.

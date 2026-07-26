# Pile technique

| Brique | Rôle | Référence |
|---|---|---|
| [CTFd](https://github.com/CTFd/CTFd) | Interface web (scores, flags, équipes) — géré comme service systemd | ctfd.io |
| [CTFdDockerContainersPlugin](https://github.com/Bigyls/CTFdDockerContainersPlugin) | Instanciation automatique d'un conteneur par équipe depuis CTFd | — |
| [Docker](https://www.docker.com/) | Construction et stockage des images de challenges | — |
| [containerd](https://containerd.io/) | Runtime de conteneurs, exécution des instances et lien avec CTFd | — |
| [Tailscale](https://tailscale.com/) | Accès sécurisé à la plateforme (réseau privé virtuel) + HTTPS (Let's Encrypt) | — |
| [Grafana](https://grafana.com/) + [Prometheus](https://prometheus.io/) | Supervision (métriques, dashboards, alerting) | voir [SUPERVISION.md](SUPERVISION.md) |
| [Healthchecks.io](https://healthchecks.io/) | *Dead man's switch* externe (détection panne totale de l'hôte) | — |
| [Benchmark CIS Debian](https://www.cisecurity.org/benchmark/debian_linux) | Référentiel de durcissement du serveur | voir [security.md](security.md) |

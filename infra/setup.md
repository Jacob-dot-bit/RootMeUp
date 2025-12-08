# Installation et déploiement

## Prérequis
- 2 VM (VM1 pour CTFd, VM2 pour challenges)
- Docker + Docker Compose
- Kubernetes (minikube ou cluster école)
- Accès SSH par clé uniquement

## Étapes futures
1. Durcissement des VM (SSH, iptables, fail2ban) [en cours]
2. Installation CTFd sur VM1
3. Déploiement Kubernetes sur VM1/VM2
4. Scripts de backup PRA

## Fichiers à venir
- `docker-compose.yml` : CTFd + base de données
- `k8s/` : manifests pour challenges
- `scripts/` : durcissement + backups

# Installation et déploiement

## Prérequis
- Une VM Debian (durcie selon le benchmark CIS)
- Docker et containerd installés
- Tailscale installé sur la VM
- Accès SSH par clé uniquement (connexion root interdite)

## Étapes de déploiement

1. **Durcissement du serveur** (SSH, iptables, fail2ban, auditd, unattended-upgrades)
2. **Installation de CTFd** comme service systemd (port 8000)
3. **Installation du plugin** [CTFdDockerContainersPlugin](https://github.com/Bigyls/CTFdDockerContainersPlugin) dans CTFd
4. **Chargement des images Docker** des challenges sur le serveur
5. **Création des challenges** dans CTFd (type `container`) avec image, port et commande

## Transfert d'une image Docker vers le serveur

```powershell
# Depuis PowerShell (Windows)
scp -i "C:\Users\Admin\.ssh\Projet Annuel\jakub_ssh_key" ".\mon-challenge.tar" jakub@<IP_TAILSCALE_VM>:/tmp/
```

Sur le serveur :

```bash
docker load -i /tmp/mon-challenge.tar
docker images | grep mon-challenge
```

## Accès au serveur

L'accès se fait via Tailscale. Rejoindre le réseau avec le lien d'invitation, puis :

```bash
ssh -i "chemin/vers/cle_privee" jakub@<IP_TAILSCALE_VM>
```

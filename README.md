# RootMeUp

Plateforme CTF open-source pour étudiants et professionnels cybersécurité. Challenges progressifs Blue/Red Team, conteneurisés et isolés par équipe.

## Objectif
- Challenges pratiques isolés par équipe (3 participants)
- Visualisation des scores et saisie des flags via l'interface CTFd
- Environnement pédagogique gratuit et francophone

## Architecture

Le serveur est une VM Debian durcie selon le benchmark CIS, qui héberge :
- **CTFd** : géré comme un service systemd, accessible sur le port 8000
- **Docker** : utilisé pour construire et stocker les images des challenges
- **containerd** : runtime de conteneurs qui exécute effectivement les instances de challenges ; sert de lien entre CTFd et les conteneurs lancés
- **CTFdDockerContainersPlugin** : plugin CTFd qui déclenche via containerd la création d'une instance par équipe lors du lancement d'un challenge

L'accès à la plateforme se fait via **Tailscale** (réseau privé virtuel), ce qui évite d'exposer le serveur directement sur Internet.

## Prérequis

### Côté serveur
- Debian (durci CIS)
- Docker et containerd installés
- CTFd installé et configuré comme service systemd
- Plugin [CTFdDockerContainersPlugin](https://github.com/Bigyls/CTFdDockerContainersPlugin) installé dans CTFd
- Tailscale installé sur la VM

### Côté client
- Client Tailscale installé : https://tailscale.com/download
- Invitation au réseau Tailscale du projet (fournie par l'équipe)

## Accès à la plateforme

1. Installer Tailscale sur votre poste et se connecter
2. Rejoindre le réseau via le lien d'invitation fourni
3. Récupérer l'IP Tailscale de la VM sur https://login.tailscale.com/admin/machines
4. Accéder à CTFd dans le navigateur :

```
http://<IP_TAILSCALE_VM>:8000
```

5. Créer un compte, rejoindre ou créer une équipe (3 participants max)

## Lancement d'un challenge

1. Ouvrir la liste des challenges dans CTFd
2. Sélectionner un challenge
3. Cliquer sur **Start Instance** — CTFdDockerContainersPlugin crée une instance Docker dédiée à votre équipe
4. Se connecter à l'instance via l'URL/port indiqués
5. Soumettre le flag dans l'interface CTFd

## Challenges disponibles

| # | Nom | Catégorie | Statut |
|---|-----|-----------|--------|
| 1 | Phishing sur corp.local — analyse de logs post-incident | Blue Team | Intégré |
| 2 | Mémoire et analyse de malware (Volatility) | Blue Team | Intégré |
| 3 | LFI jusqu'au flag | Red Team | En cours |
| 4 | Détection dans les logs (SIEM / ELK) | Blue Team | En cours |

## Ajout d'un challenge sur le serveur

Construire l'image Docker localement, l'exporter et la transférer sur le serveur :

```powershell
# Depuis PowerShell (Windows)
scp -i "C:\Users\Admin\.ssh\Projet Annuel\jakub_ssh_key" ".\mon-challenge.tar" jakub@<IP_TAILSCALE_VM>:/tmp/
```

Sur le serveur, importer l'image :

```bash
docker load -i /tmp/mon-challenge.tar
docker images | grep mon-challenge
```

Puis créer le challenge dans CTFd (`Admin Panel > Challenges > Create Challenge > Type: container`) en renseignant l'image, le port et la commande de démarrage.

## Durcissement du serveur

Mesures appliquées conformément au benchmark CIS Debian :
- Accès SSH par clé uniquement, connexion root interdite
- Pare-feu `iptables` filtrant les flux entrants/sortants
- Mises à jour automatiques (`unattended-upgrades`)
- Politique de mots de passe stricte pour les comptes locaux
- `auditd` configuré (changements de mots de passe, modifications de fichiers sensibles)
- `Fail2Ban` contre les tentatives de brute force

## Équipe projet

| Membre | Rôle |
|--------|------|
| Jakub | Chef de projet |
| Sarah | Architecte cybersécurité |
| Evan | Développeur cybersécurité |
| Lucas | Développeur et concepteur de challenges |

## Liens utiles

- Suivi des tâches (Trello) : https://trello.com/b/noVfLRlC/rootmeup
- Dépôt GitHub : https://github.com/Jacob-dot-bit/RootMeUp
- Plugin CTFd : https://github.com/Bigyls/CTFdDockerContainersPlugin

## Licence

Licence MIT (projet open source éducatif). Voir le fichier `LICENSE`.

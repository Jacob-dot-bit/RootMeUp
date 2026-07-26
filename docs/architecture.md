# Architecture RootMeUp

```mermaid
flowchart LR
    joueur["👤 Joueur<br/>(navigateur / SSH / nc)"]

    subgraph tailnet["Réseau privé Tailscale"]
        direction TB
        subgraph vm["VM Debian durcie (CIS)"]
            apache["Apache :443 (HTTPS)<br/>cert Let's Encrypt (tailscale cert)"]
            ctfd["CTFd<br/>(systemd, gunicorn :8000)"]
            plugin["CTFdDockerContainersPlugin"]
            docker["Docker + containerd"]
            inst["Instances de challenges<br/>(1 conteneur / équipe)"]
        end
    end

    joueur -->|VPN| apache --> ctfd --> plugin
    plugin -->|pilote| docker --> inst
    joueur -.->|accès direct à l'instance<br/>port dynamique| inst
```

## Composants

- **CTFd** : interface web pour les joueurs, gestion des équipes, scores et flags. Service systemd (gunicorn en local sur `127.0.0.1:8000`) ; Apache termine le TLS sur `:443` (cert Let's Encrypt via `tailscale cert`), accessible uniquement sur le tailnet.
- **containerd** : runtime de conteneurs, exécute les instances de challenges et fait le lien avec CTFd.
- **Docker** : utilisé pour construire et stocker les images des challenges.
- **CTFdDockerContainersPlugin** : plugin CTFd qui déclenche via containerd la création d'une instance isolée par équipe lors du lancement d'un challenge.
- **Tailscale** : réseau privé virtuel permettant l'accès sécurisé à la plateforme sans exposer le serveur sur Internet.

## Infrastructure

Une seule VM Debian, durcie selon le benchmark CIS, héberge l'ensemble des services :
- CTFd (systemd, port 8000)
- Docker + containerd
- Les images des challenges (chargées localement)

## Flux réseau

- **Joueurs → CTFd** (`https://ctf-rootmeup.tail8588a8.ts.net/`, sur le tailnet) : authentification, consultation des challenges, soumission des flags. Apache termine le TLS sur `:443` et proxifie vers gunicorn (`127.0.0.1:8000`).
- **CTFd → containerd** : le plugin crée une instance Docker par équipe à la demande.
- **Joueurs → instance du challenge** : connexion directe au port exposé par le conteneur.
- **Administrateurs → VM** : accès SSH par clé via Tailscale.

## Sécurité et isolation

- Un conteneur par équipe et par challenge, réseau dédié pour limiter les mouvements latéraux.
- Flags stockés côté serveur (CTFd) et injectés au runtime dans les conteneurs.
- Accès SSH par clé uniquement, connexion root interdite.
- Pare-feu `iptables`, `Fail2Ban`, `auditd`, `unattended-upgrades`.
- Accès à la plateforme restreint au réseau Tailscale.

## Exploitation

- Démarrage CTFd : `sudo systemctl start ctfd`
- Chargement d'une image : `docker load -i /tmp/image.tar`
- Vérification des conteneurs actifs : `docker ps`
- Vérification du port CTFd : `ss -tlnp | grep 8000`

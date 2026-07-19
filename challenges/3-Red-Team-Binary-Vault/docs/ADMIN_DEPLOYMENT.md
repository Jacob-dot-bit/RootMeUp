# Guide admin / déploiement — VAULT-9 (Red Team 3)

## Résumé technique

| Élément | Valeur |
|---|---|
| Type CTFd | Container (plugin CTFdDockerContainersPlugin) |
| Port interne | `9003` (TCP, servi par `socat`, une instance/connexion) |
| Fichier à joindre au challenge | le binaire **`vault`** (voir extraction ci-dessous) |
| Flags | 2 — voir `solution/SOLUTION.md` |
| Compilation | `-fno-stack-protector -no-pie -fno-pie -O0` |

Les secrets (licence, flags) sont générés au build par `setup/gen_secret.py` et **ne sont pas embarqués** dans le binaire (lus depuis `/challenge/flag*.txt` au runtime). `strings vault` ne révèle donc rien.

> ✅ **Validé bout-en-bout en conteneur Docker le 20/07/2026** : build OK,
> service accessible sur 9003, exploit `solution/exploit.py` récupère les 2 flags.

## Prérequis / pièges courants

- **Compose v1 vs v2** : `docker compose` (avec espace) n'existe qu'avec le plugin v2.
  Sur Kali/Debian, le paquet `docker-compose` (2.40.x) fournit la commande
  **`docker-compose`** (avec tiret). Si `docker compose up --build` renvoie
  `unknown flag: --build`, utilisez `docker-compose` ou la méthode build/run manuelle ci-dessous.
- **Droits Docker** : si le user n'est pas dans le groupe `docker`, préfixer chaque
  commande par `sudo` (sinon `permission denied ... /var/run/docker.sock`).

## Build & test local

```bash
cd challenges/3-Red-Team-Binary-Vault
docker-compose up --build -d      # ou : docker compose up --build -d (plugin v2)
# le service écoute sur le port 9003
nc 127.0.0.1 9003
```

Sans Compose (marche partout) :

```bash
docker build -t rt3-vault .
docker run -d -p 9003:9003 --name rt3-vault rt3-vault
```

Test automatique de la solution :

```bash
# extraire le binaire de l'image dans solution/, puis lancer l'exploit :
docker cp rt3-vault:/challenge/vault solution/vault
cd solution && python3 exploit.py 127.0.0.1 9003
```

Arrêt :

```bash
docker compose down
```

## Extraire le binaire à distribuer

Le joueur doit télécharger le **même** binaire que celui déployé :

```bash
docker compose up --build -d
docker cp rt3-vault:/challenge/vault ./vault
docker compose down
```

Joindre `./vault` comme fichier du challenge dans CTFd. **Ne jamais** joindre `flag1.txt`, `flag2.txt` ni `secret.h`.

## Intégration CTFd (plugin conteneurs)

1. Builder l'image sur l'hôte Docker de la VM (`docker build -t rt3-vault .`).
2. Dans CTFd → challenge de type **Container** : image `rt3-vault`, port interne **9003**.
3. Renseigner les 2 flags (sensibles à la casse), en points progressifs.
4. Joindre le binaire `vault` (fichier téléchargeable).
5. Tester le **Start Instance** avec un compte non-admin (IP + port dynamique alloués par le plugin).

## Sécurité de déploiement

- Le conteneur tourne en utilisateur non privilégié `ctf`, `nologin`.
- Le binaire est volontairement vulnérable **mais confiné au conteneur** : aucun accès hôte, pas de shell exposé (le ret2win n'offre qu'un `puts` du flag, pas de RCE arbitraire).
- `socat` limite chaque session (`-T120`, timeout 120 s) pour éviter les connexions pendantes.

## Modifier les flags / la licence

Éditer `setup/gen_secret.py` (constantes `LICENSE`, `XOR_KEY`, `FLAG1`, `FLAG2`) puis rebuilder. Penser à régénérer/rejoindre le binaire et à mettre à jour les flags dans CTFd.

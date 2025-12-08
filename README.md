# RootMeUp

Plateforme CTF open-source pour étudiants et professionnels cybersécurité. Trois challenges progressifs Blue/Red Team, conteneurisés et sécurisés.

## 🎯 Objectif
- Challenges pratiques isolés par équipe (3 participants)
- Visualisation des scores et saisie des flags via l’interface CTFd
- Environnement pédagogique gratuit et francophone

## 🚧 Prérequis
- Docker et docker-compose (ou Podman) installés
- Accès réseau aux ports exposés par CTFd (par défaut 8000) et aux challenges
- Optionnel : reverse proxy (Nginx/Traefik) pour le TLS et le rate limiting

## ⚙️ Installation
```bash
git clone <https://github.com/Jacob-dot-bit/RootMeUp>
cd RootMeUp
```
Préparez vos fichiers d’environnement (`.env`) pour CTFd et les challenges (secrets, flags, clés). Placez vos images de challenges dans un registry accessible ou construisez-les localement.

## 🧾 Configuration (.env)
Créer/ajuster ces fichiers avant le démarrage :
- `.env` (racine) : variables docker-compose (ports, tags d’images, options du reverse proxy si utilisé).
- `ctfd/.env` : secrets et paramètres CTFd.
- `challenges/<nom>/.env` : secrets/flags par challenge (ne pas les versionner).

Exemple minimal pour `ctfd/.env` :
```env
CTFD_SECRET_KEY=change-me
DATABASE_URL=postgresql://ctfd:ctfd@db/ctfd
REDIS_URL=redis://redis:6379/0
CTFD_LOG_LEVEL=INFO
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=change-me
```
Bonnes pratiques : gardez vos `.env` hors du dépôt git, fournissez un `.env.example` si besoin, et faites tourner régulièrement les secrets/flags.

## ▶️ Démarrage (exemple docker-compose)
```bash
docker-compose up -d
```
Services attendus :
- `ctfd` (web + API)
- `db` (base de données CTFd)
- `challenge-*` (un conteneur par challenge)

## 🔗 Accès
- Interface CTFd : http://localhost:8000 (ou derrière votre proxy TLS)
- Soumission des flags : via l’UI CTFd
- Administration : compte admin défini dans les variables d’environnement CTFd

## 🧩 Challenges (aperçu)
- Challenge 1 : Blue Team — triage et analyse
- Challenge 2 : Red Team — exploitation contrôlée
- Challenge 3 : Mixte — investigation + pivot

## 🏗️ Architecture
![schéma](./docs/diagram.png)
Détails : [docs/architecture.md](docs/architecture.md)

## 🔒 Bonnes pratiques opérationnelles
- Isoler chaque challenge sur un réseau dédié, exposer uniquement les ports nécessaires
- Stocker les flags côté serveur, les injecter au runtime, et les faire tourner régulièrement
- Activer les journaux d’accès CTFd et des conteneurs, surveiller la charge
- Sauvegarder la base CTFd et la configuration; tester la restauration

## 📄 Licence
Licence MIT (adaptée à un projet open source éducatif). Le fichier `LICENSE` contient le texte complet.
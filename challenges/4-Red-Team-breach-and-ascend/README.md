# 🔴 Red Team 4 — Breach & Ascend

**Auteur :** Lucas
Intrusion d'une **application web** (upload de fichiers) puis **élévation de privilèges**
pas à pas jusqu'à `root`.

## 🎯 Résumé

| | |
|---|---|
| Catégorie | Red Team — Web → élévation de privilèges |
| Difficulté | Intermédiaire |
| Flags | **3** progressifs — format `FLAG{...}` (sensible à la casse) |
| Accès joueur | **HTTP** (web) — `http://<ip>:<port>/` |
| Image / Port | `rt4-beach-and-ascend:1.3` ⚠️ · port interne **80** |

## 📖 Scénario

Une application web d'entreprise (fictive) expose une fonctionnalité d'**upload**. Le joueur
prend pied sur le serveur via l'application, puis **remonte les privilèges** jusqu'à `root`.

## 🚩 Objectifs (flags)

1. **Breach** — compromettre l'application web et obtenir un premier accès (foothold) — 100 pts
2. **Pivot vers user** — passer de l'accès web à un compte utilisateur — 50 pts
3. **Root** — élever les privilèges jusqu'à `root` — 200 pts

## 🧩 Déploiement

```bash
docker build -t rt4-beach-and-ascend:1.3 .
```
Câblage CTFd : type `container`, image ci-dessus, port **80**, 3 flags `Static` (`FLAG{...}`).

> ⚠️ **Nom d'image à harmoniser** : l'image s'appelle `rt4-beach-and-ascend` (coquille
> « beach » → « breach ») et **sans le préfixe `rootmeup/`**. Recommandé :
> `rootmeup/rt4-breach-and-ascend:1.0` (aligner l'image buildée, le tag dans CTFd et ici).

## 🗂️ Structure

```
Dockerfile              ← build (serveur web PHP)
web/index.php           ← page d'accueil
web/upload.php          ← fonctionnalité d'upload (vecteur d'intrusion)
web/config.php          ← configuration de l'application
web/assets/style.css
web/uploads/            ← répertoire d'upload (.gitkeep, .htaccess)
```

## 📚 Documentation

- Solution / write-up : _à ajouter par Lucas (`solution/SOLUTION.md`)._
- Guide joueur (sans spoiler) : dépôt joueurs `RootMeUp-CTF`

> _TODO Lucas : renommer l'image en `rootmeup/rt4-breach-and-ascend`, ajouter un write-up._

# 🔴 Red Team 3 — Nexus Cipher

**Auteur :** Sarah
Pentest d'un **portail d'API interne** développé « maison » : mauvaise gestion des secrets,
contrôle d'accès approximatif et **cryptographie artisanale** à casser.

## 🎯 Résumé

| | |
|---|---|
| Catégorie | Red Team — Pentest d'API (web / crypto) |
| Difficulté | Intermédiaire → avancé |
| Flags | **10** progressifs — format `RootMeUp{...}` (sensible à la casse) |
| Accès joueur | **HTTP** (API) — `curl http://<ip>:<port>/` |
| Image / Port | `rootmeup/rt3-ciphers-nexus:1.0` · port interne **8080** |

## 📖 Scénario

**Nexus** est l'API interne d'une entreprise fictive. Elle expose plusieurs endpoints
(authentification, ressources, échanges chiffrés). Le joueur doit l'auditer de bout en bout
et récupérer les **10 flags** en exploitant sa logique, ses failles de contrôle d'accès et
ses faiblesses cryptographiques.

## 🚩 Objectifs (flags)

1. Reconnaissance de l'API
2. Contournement d'authentification
3. Signature serveur fragile
4. Accès aux données d'autrui (IDOR)
5. Falsification de rôle
6. Déchiffrement sans clé
7. Prédiction d'un jeton
8. Exécution détournée
9. Falsification de requête signée
10. Compromission finale

## 🧩 Déploiement

```bash
docker build -t rootmeup/rt3-ciphers-nexus:1.0 .
```
Câblage CTFd : type `container`, image ci-dessus, port **8080**, 10 flags `Static` (`RootMeUp{...}`).

## 🗂️ Structure

```
Dockerfile              ← build de l'application
app/app.py              ← application (API Flask)
app/requirements.txt    ← dépendances Python
app/templates/index.html
GUIDE_DEPLOIEMENT.md     ← guide de déploiement (Sarah)
WALKTHROUGH.md          ← ⚠️ solution pas à pas (spoilers)
```

## 📚 Documentation

- Déploiement : [`GUIDE_DEPLOIEMENT.md`](GUIDE_DEPLOIEMENT.md)
- Solution (⚠️ **spoilers**) : [`WALKTHROUGH.md`](WALKTHROUGH.md)
- Guide joueur (sans spoiler) : dépôt joueurs `RootMeUp-CTF`

> _TODO Sarah : vérifier/compléter les intitulés exacts des 10 flags si besoin._

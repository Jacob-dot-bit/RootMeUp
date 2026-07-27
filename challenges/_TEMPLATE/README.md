<!--
TEMPLATE de README de challenge — copiez ce fichier dans votre dossier
`challenges/N-Team-Nom-Auteur/README.md` et remplissez les champs.
Objectif : que chaque challenge se présente de la même façon (cohérence dépôt).
-->

# <🔵/🔴> <Blue/Red> Team <N> — <Nom du challenge>

**Auteur :** <Prénom>
_Une phrase d'accroche : ce que le joueur va faire / apprendre._

## 🎯 Résumé

| | |
|---|---|
| Catégorie | <Blue/Red Team — sous-domaine (forensic réseau, reverse+pwn, web→root, crypto/API…)> |
| Difficulté | <Débutant / Intermédiaire / Avancé> |
| Flags | <nombre> — format `<RootMeUp{...} / FLAG{...} / valeur brute>` (sensible à la casse) |
| Accès joueur | <SSH `user@ip -p port` / HTTP(S) / `nc ip port` / téléchargement d'un fichier> |
| Image / Port | `rootmeup/<code>:1.0` · port interne `<EXPOSE>` |

## 📖 Scénario

_Contexte narratif du challenge (l'entreprise fictive, l'incident, l'objectif)._

## 🚩 Objectifs (flags)

1. **Flag 1 — <titre>** : <ce qu'il faut trouver/faire>
2. **Flag 2 — <titre>** : …

## 🧩 Déploiement

```bash
# depuis ce dossier, sur le serveur (voir docs/DEPLOIEMENT.md)
docker build -t rootmeup/<code>:1.0 .
```
- Flags rotés hors dépôt via `setup/challenge.env` (si applicable — voir `challenge.env.example`).
- Câblage CTFd : type `container`, image + port ci-dessus, flag(s) `Static`.

## 🗂️ Structure

```
<arborescence des fichiers importants + une ligne d'explication chacun>
```

## 📚 Documentation

- Guide joueur (sans spoiler) : `docs/USER_GUIDE.md` (ou le dépôt joueurs `RootMeUp-CTF`)
- Déploiement admin : `docs/ADMIN_DEPLOYMENT.md`
- Solution (⚠️ **spoilers**) : `solution/SOLUTION.md`

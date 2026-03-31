# 🔵 Blue Team CTF – Mémoire et Analyse de Malware
### Challenge Jakub – Forensique Mémoire avec Volatility

## 📌 Documentation
- Guide joueur: `docs/USER_GUIDE.md`
- Guide admin/deploiement: `docs/ADMIN_DEPLOYMENT.md`

---

## 📖 Contexte

L'équipe SOC a été alertée d'un comportement suspect sur la machine **DESKTOP-F4K3LAB** du réseau interne. Un analyste junior a immédiatement effectué un dump mémoire de la VM Windows compromise avant de l'isoler du réseau.

L'investigation préliminaire suggère que **l'attaquant a déployé un implant en mémoire qui communique avec un serveur C2 (Command & Control)**. Votre mission est d'analyser ce dump mémoire pour identifier la menace, extraire les artefacts malveillants et récupérer les preuves.

> 🎯 **Objectif** : Trouver le processus malveillant, identifier le C2, et récupérer le flag caché.

---

## 📁 Structure du Challenge

```
Blue-Team-Memory-Forensics/
├── README.md                          ← Vous êtes ici
├── Dockerfile                         ← Image du challenge
├── docker-compose.yml                 ← Orchestration Docker
├── docker-entrypoint.sh               ← Script d'accueil du conteneur
├── .dockerignore                      ← Fichiers exclus du build
├── challenge/                         ← (généré au build Docker)
│   ├── memory.dmp                     ← Dump mémoire à analyser
│   ├── network_capture.pcap           ← Capture réseau bonus
│   └── hints.txt                      ← Indices (si besoin)
├── tools/
│   ├── vol_analyzer.py                ← Outil d'analyse (mini-Volatility)
│   └── extract_strings.py             ← Extracteur de chaînes
├── setup/
│   ├── generate_challenge.py          ← Générateur du dump (admin only)
│   ├── generate_pcap.py               ← Générateur du PCAP (admin only)
│   └── requirements.txt               ← Dépendances Python
├── solution/
│   ├── SOLUTION.md                    ← Solution complète (⚠️ SPOILERS)
│   └── validate_flag.py               ← Script de validation
└── report/
    └── report_template.md             ← Template de rapport à remplir (partagé)
```

---

## 🎯 Public cible

Ce depot contient deux parcours de documentation :
- Joueurs CTF : `docs/USER_GUIDE.md`
- Admins/DevOps (deploiement) : `docs/ADMIN_DEPLOYMENT.md`

## ✅ Usage recommande

- Si vous etes joueur : commencez par `docs/USER_GUIDE.md`
- Si vous deployez le challenge dans CTFd : suivez `docs/ADMIN_DEPLOYMENT.md`

## 🔎 Notes

- Le challenge est conteneurise pour l'isolation des instances.
- Le mode soutenance actuel expose les artefacts via HTTP depuis le conteneur.
- Le detail de configuration CTFd, du flag et du troubleshooting est volontairement deplace dans `docs/ADMIN_DEPLOYMENT.md`.

---

## ⚠️ Avertissement

Ce challenge est conçu à des fins **éducatives uniquement**. Les techniques présentées doivent être utilisées de manière éthique et légale, uniquement dans des environnements autorisés.

---

*Blue Team CTF – Jakub – ESGI Projet Annuel 2026*
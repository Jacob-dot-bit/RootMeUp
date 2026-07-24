# 🔴 Red Team 3 — VAULT-9 (Reverse & Exploitation binaire)

### Challenge Jakub — niveau intermédiaire

Premier challenge de **pwn** de la plateforme RootMeUp : un binaire Linux à
rétro-ingénier puis à exploiter. Conçu pour combler l'écart entre les Blue Team
(accessibles) et les Red Team 1 & 2 (Linux/web).

## 📌 Documentation

- Guide joueur : [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md)
- Guide admin / déploiement : [`docs/ADMIN_DEPLOYMENT.md`](docs/ADMIN_DEPLOYMENT.md)
- Solution (⚠️ spoilers) : [`solution/SOLUTION.md`](solution/SOLUTION.md)

## 🎯 Résumé

| | |
|---|---|
| Catégorie | Red Team — Reverse + Exploitation binaire |
| Difficulté | Intermédiaire |
| Flags | 2 (progressifs) |
| Accès | `nc <ip> <port>` (instance Docker par équipe) |
| Compétences | reverse (XOR), débordement de tampon, ret2win, pwntools |

## 🧩 Déroulé

1. **Reverse** — la console vérifie une licence obfusquée en XOR (`check_license`). Le joueur récupère la clé → **flag 1**.
2. **Exploitation** — le terminal de maintenance déborde `buf[64]` (lecture de 200 octets). Le joueur détourne l'exécution (`ret2win`) vers la fonction cachée `vault()` → **flag 2**.

## 📁 Structure

```
1-Red-Team-Binary-Vault-Jakub/
├── README.md
├── Dockerfile                  ← build + service socat (port 9003)
├── docker-compose.yml          ← test local
├── docker-entrypoint.sh
├── challenge/
│   └── vault.c                 ← source du binaire (sans secret en clair)
├── setup/
│   └── gen_secret.py           ← génère secret.h + flags au build (⚠️ spoiler)
├── docs/
│   ├── USER_GUIDE.md
│   └── ADMIN_DEPLOYMENT.md
├── solution/
│   ├── SOLUTION.md             ← ⚠️ spoilers
│   └── exploit.py              ← exploit pwntools (testé)
└── report/
    └── report_template.md
```

## ⚙️ Build rapide

```bash
docker compose up --build -d      # écoute sur 9003
nc 127.0.0.1 9003
docker compose down
```

> Artefacts générés (`secret.h`, `flag*.txt`, `vault`) : ignorés par git, jamais committés.

# 🔵 Blue Team CTF – Hardening / Durcissement Système
## Challenge Lucas – Sécurisation d'un serveur Linux (Operation IRON GATE)

### 📌 Documentation
- Guide joueur : `docs/USER_GUIDE.md`
- Guide admin / déploiement : `docs/ADMIN_DEPLOYMENT.md`

### 📖 Contexte
La société **NORTHWIND Trading Co.** vient de récupérer un vieux serveur,
**srv-legacy01**, hérité d'un prestataire parti sans documentation. L'audit
initial est alarmant : connexion root SSH autorisée, compte caché en UID 0,
tâche cron suspecte, secret applicatif en clair, service telnet actif…

Vous êtes le **nouvel administrateur Blue Team**. Votre mission n'est pas
d'analyser une attaque passée, mais d'**empêcher la prochaine** : durcir le
serveur avant qu'un attaquant n'en profite.

🎯 **Objectif** : corriger les **10 mauvaises configurations** du serveur.
Chaque faille corrigée révèle un **flag** à soumettre dans CTFd.

### 🖥️ Comment ça marche
- Cliquez sur **Start Instance** dans CTFd → un **terminal web** s'ouvre (le serveur srv-legacy01).
- Vous êtes connecté en tant qu'utilisateur **`analyst`** (avec `sudo`).
- Tapez la commande **`audit`** : elle affiche votre **progression** (ce qui reste à corriger), niveau par niveau.
- Corrigez les failles. La **validation et l'attribution des flags se font côté serveur** (le joueur, même root sur son instance, n'a aucun flag stocké localement à voler ou à reverser).

> 🔒 **Anti-triche par conception** : aucun flag n'existe dans le conteneur. Un
> valideur côté serveur (`grader/grade.py`) inspecte l'état de l'instance et ne
> délivre un flag qu'une fois le correctif réellement appliqué. Voir
> `docs/ADMIN_DEPLOYMENT.md`.

### 📁 Structure du challenge
```
3-Blue-Team-Hardening/
├── README.md                   ← Vous êtes ici
├── Dockerfile                  ← Image (terminal web ttyd + serveur vulnérable)
├── docker-entrypoint.sh        ← Point d'entrée du conteneur
├── supervisord.conf            ← Orchestration (ttyd)
├── .dockerignore
├── setup/
│   └── harden_setup.sh         ← Déploie l'état vulnérable au build (admin only)
├── audit/
│   └── checker.c               ← Auto-évaluation joueur (progression seule, AUCUN flag)
├── setup/
│   ├── harden_setup.sh         ← Déploie l'état vulnérable au build (admin only)
│   └── getflag                 ← Client joueur : réclame un flag au serveur (aucun flag dedans)
├── grader/                     ← CÔTÉ SERVEUR (hors conteneur) — détient les flags
│   ├── checks.py               ← Logique des 10 contrôles (source de vérité + flags)
│   ├── grade.py                ← Valideur CLI (admin : --target / --ssh / --task)
│   └── grade_server.py         ← Service HTTP interrogé par `getflag` (docker exec)
├── docs/
│   ├── USER_GUIDE.md           ← Guide joueur
│   └── ADMIN_DEPLOYMENT.md     ← Guide admin et déploiement
├── ctfd/
│   ├── challenges.yml          ← Définition des 10 challenges CTFd (déblocage progressif)
│   └── flags.txt               ← Récap des flags (admin only)
├── solution/
│   ├── SOLUTION.md             ← Correctifs détaillés (⚠️ SPOILERS)
│   └── verify_hardening.sh     ← Test auto de la logique d'audit (avant/après)
└── report/
    └── report_template.md      ← Template de rapport de durcissement
```

### 🔎 Notes techniques
- Conteneur **Docker isolé par équipe** (via `CTFdDockerContainersPlugin`).
- Accès par **terminal web (ttyd)** sur le **port 8000** assigné dynamiquement par CTFd.
- Démarrage en **quelques secondes**.
- Progression **flag par flag** : les 10 questions se débloquent progressivement dans CTFd.

### 🧭 Distinction avec les autres challenges Blue Team
| Challenge | Compétence | Posture |
|-----------|-----------|---------|
| Sarah – SIEM/ELK | Analyse de logs | Réactif (forensique) |
| Jakub – Mémoire/Volatility | Analyse mémoire | Réactif (forensique) |
| **Lucas – Hardening** | **Durcissement système** | **Proactif (défense)** |

### ⚠️ Avertissement
Ce challenge est conçu à des fins **éducatives uniquement**. Les techniques
présentées doivent être utilisées de manière éthique et légale, uniquement dans
des environnements autorisés.

*Blue Team CTF – Lucas – ESGI Projet Annuel 2026*

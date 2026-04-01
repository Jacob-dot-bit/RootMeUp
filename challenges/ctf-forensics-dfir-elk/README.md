# Blue Team CTF – DFIR Incident CORP.LOCAL
### Challenge Evan – Forensique via SIEM / ELK

## Documentation
- Guide joueur : `docs/USER_GUIDE.md`
- Guide admin/déploiement : `GUIDE_DEPLOIEMENT.md`

---

## Contexte

Le domaine **CORP.LOCAL** a été victime d'une intrusion. L'équipe SOC a collecté les journaux Windows des machines impactées et les a centralisés dans une instance **Kibana** mise à votre disposition.

L'investigation préliminaire indique qu'un attaquant a compromis un poste utilisateur, pivoté vers un serveur applicatif, puis s'est attaqué au Domain Controller.

> **Objectif** : Analyser les logs dans Kibana, reconstituer la chaîne d'attaque et répondre aux 10 questions du challenge.

---

## Infrastructure du scénario

| Machine | Rôle | IP |
|---------|------|----|
| `WIN-ACCT01` | Poste utilisateur compromis | 192.168.10.45 |
| `APP-SRV01` | Serveur applicatif (pivot) | 192.168.10.52 |
| `DC01` | Domain Controller (cible finale) | 192.168.10.10 |

---

## Structure du challenge

```
ctf-forensics-dfir-elk/
├── README.md                  <- Vous êtes ici
├── Dockerfile                 <- Image du challenge (ELK tout-en-un)
├── GUIDE_DEPLOIEMENT.md       <- Guide admin complet
├── supervisord.conf           <- Orchestration des services ELK
├── pipeline/
│   └── logstash.conf          <- Pipeline d'ingestion des logs
└── init/
    ├── inject_logs.py         <- Injection des logs dans Elasticsearch
    └── import_kibana.sh       <- Import des index patterns Kibana
```

---

## Public cible

- **Joueurs CTF** : commencez par `docs/USER_GUIDE.md`
- **Admins / déploiement** : suivez `GUIDE_DEPLOIEMENT.md`

---

## Notes techniques

- Le challenge tourne dans un conteneur Docker isolé par équipe (via CTFdDockerContainersPlugin).
- Chaque instance embarque Elasticsearch, Kibana et Logstash dans un seul conteneur.
- L'accès se fait via le port Kibana (5601) assigné dynamiquement par CTFd.
- L'instance peut prendre **2 à 3 minutes** à démarrer le temps qu'Elasticsearch soit prêt.

---

## Avertissement

Ce challenge est conçu à des fins **éducatives uniquement**. Les techniques présentées doivent être utilisées de manière éthique et légale, uniquement dans des environnements autorisés.

---

*Blue Team CTF – Evan – ESGI Projet Annuel 2026*

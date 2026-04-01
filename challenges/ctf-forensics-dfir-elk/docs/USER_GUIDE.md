# Guide joueur – DFIR Incident CORP.LOCAL

## Contexte

Un incident de sécurité s'est produit sur le domaine **CORP.LOCAL**. Vous avez accès à une instance **Kibana** contenant les journaux Windows collectés sur les machines impactées.

Votre mission : analyser les logs, reconstituer la chaîne d'attaque et répondre aux questions du challenge.

---

## Accès à votre instance Kibana

1. Sur la page du challenge dans CTFd, cliquer sur **Start Instance**
2. Attendre **2 à 3 minutes** — Elasticsearch doit démarrer avant que Kibana soit disponible
3. Une URL s'affiche dans CTFd : `http://<IP_TAILSCALE_VM>:<port_assigné>`
4. Ouvrir cette URL dans votre navigateur → vous arrivez sur Kibana

> Si Kibana affiche une erreur au premier chargement, patientez encore une minute et rafraîchissez.

---

## Prise en main de Kibana

### Accéder aux logs

1. Dans Kibana, aller dans **Discover** (menu de gauche)
2. Sélectionner l'index pattern `dfir-incident-*`
3. Les logs des trois machines s'affichent dans l'ordre chronologique

### Filtrer par machine

Dans la barre de recherche, utiliser :

```
host.name: "WIN-ACCT01"
host.name: "APP-SRV01"
host.name: "DC01"
```

### Filtrer par type d'événement Windows

```
event.code: 4624        <- Connexion réussie
event.code: 4625        <- Connexion échouée
event.code: 4688        <- Création de processus
event.code: 4698        <- Tâche planifiée créée
event.code: 4720        <- Compte créé
event.code: 4728        <- Ajout à un groupe
```

### Filtrer par plage de temps

Utilisez le sélecteur de temps en haut à droite pour cibler la période de l'incident.

---

## Infrastructure du scénario

| Machine | Rôle | IP |
|---------|------|----|
| `WIN-ACCT01` | Poste utilisateur compromis (point d'entrée) | 192.168.10.45 |
| `APP-SRV01` | Serveur applicatif (pivot) | 192.168.10.52 |
| `DC01` | Domain Controller (cible finale) | 192.168.10.10 |

---

## Progression recommandée

1. **Identifier le point d'entrée** — quel poste a été compromis en premier ?
2. **Retrouver la commande initiale** — quelle commande a été exécutée au démarrage ?
3. **Identifier le script téléchargé** — quel fichier l'attaquant a-t-il récupéré ?
4. **Identifier l'outil d'énumération** — quel outil a été utilisé pour cartographier l'AD ?
5. **Retrouver la technique de dump** — comment l'attaquant a-t-il extrait les credentials ?
6. **Identifier le pivot** — quel compte a été utilisé pour atteindre APP-SRV01 ?
7. **Dater le pivot** — à quelle heure la première connexion RDP a-t-elle eu lieu ?
8. **Analyser l'authentification Kerberos** — quel type de ticket a été utilisé sur DC01 ?
9. **Identifier l'escalade de privilèges** — quel SID a été ajouté à un groupe privilégié ?
10. **Trouver le compte de persistance** — quel compte avec SPN a été créé pour la persistance ?

---

## Outils recommandés

- **Kibana Discover** : exploration et filtrage des logs
- **KQL (Kibana Query Language)** : requêtes avancées
- **MITRE ATT&CK** : identification des techniques (`https://attack.mitre.org`)
- **VirusTotal** : recherche de hash de fichiers suspects

---

## Format des flags

Chaque réponse est soumise sous la forme :

```
FLAG{valeur}
```

Exemple : `FLAG{192.168.10.45}`

---

## Bon courage !

*Blue Team CTF – Sarah – ESGI Projet Annuel 2026*

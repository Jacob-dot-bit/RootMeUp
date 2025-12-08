![schéma](./diagram.png)

# Architecture RootMeUp

## Composants
- **CTFd** : interface web pour les joueurs, gestion des équipes, scores, flags.
- **Containers de challenges** : un conteneur par challenge (Blue/Red), isolement réseau par challenge.
- **Base de données** : stockage CTFd (scores, utilisateurs, flags), sauvegardes régulières.
- **Reverse proxy** (optionnel) : terminaison TLS et routage vers CTFd et les challenges.

## Flux réseau
- Joueurs → CTFd (HTTP/HTTPS) pour l’authentification, la consultation des challenges et la soumission des flags.
- CTFd → containers de challenges : exposition contrôlée des ports nécessaires à chaque challenge.
- Administration → CTFd et hôtes d’infra pour gestion/maintenance.

## Sécurité et isolation
- Un conteneur par challenge, réseau dédié pour limiter les mouvements latéraux.
- Secrets/flags stockés côté serveur (CTFd) et injectés au runtime dans les conteneurs de challenge.
- Limitation des ports exposés, utilisation de TLS côté frontal (proxy ou CTFd).
- Journalisation des accès (CTFd) et des conteneurs, conservation pour analyse.

## Exploitation
- Démarrage : déployer CTFd, la base, puis les conteneurs de challenges.
- Sauvegardes : base CTFd + configuration; prévoir restauration régulière.
- Rotation des flags : renouveler périodiquement les secrets et redéployer les conteneurs concernés.
- Supervision : surveiller disponibilité CTFd, charge des hôtes, et erreurs applicatives.

## Pistes d’amélioration
- Ajouter un environnement de préprod pour tester de nouveaux challenges.
- Renforcer la protection DDoS et le rate limiting sur le frontal.
- Documenter un playbook d’exploitation (backup/restore, rotation de secrets, mises à jour).

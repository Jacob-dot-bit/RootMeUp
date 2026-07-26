# Bugs rencontrés & corrections — RootMeUp

Journal des problèmes techniques rencontrés pendant l'intégration de la plateforme et
des challenges, avec pour chacun le **symptôme**, la **cause racine** et la **correction**.
Objectif : capitaliser (retour d'expérience) et éviter que les mêmes pièges se reproduisent.

## 1. Déploiement CTFd & plugin conteneurs

### 1.1 Le bouton « Start Instance » n'apparaît pas
- **Symptôme** : sur un challenge de type *container*, aucun bouton pour lancer l'instance.
- **Cause** : le champ **Connection Info** du challenge était vide.
- **Correction** : renseigner une valeur non vide dans *Connection Info* (ex. `nc <ip> <port>`
  ou `ssh user@<ip> -p <port>`). C'est ce champ qui déclenche l'affichage du bouton.

### 1.2 « Could not get port » à la création de l'instance
- **Symptôme** : le plugin refuse de démarrer le conteneur, erreur de port.
- **Cause** : l'image Docker ne déclarait pas de port avec `EXPOSE`.
- **Correction** : ajouter `EXPOSE <port>` dans le Dockerfile (ex. `EXPOSE 9003`, `EXPOSE 22`).

### 1.3 Le conteneur meurt instantanément (connexion fermée aussitôt)
- **Symptôme** : `nc <ip> <port>` se connecte puis se ferme sans rien afficher ; aucune
  instance visible dans `docker ps`.
- **Cause** : le conteneur tourne en utilisateur non privilégié (`USER ctf`, bonne pratique),
  mais `entrypoint.sh` avait les droits `-rwxr-x--x` — **exécutable mais non lisible** par
  `others`. Or un script `#!/bin/sh` doit être **lu** par l'interpréteur pour s'exécuter →
  *Permission denied* → crash silencieux au démarrage.
- **Correction** : `RUN chmod 0755 /usr/local/bin/entrypoint.sh` dans le Dockerfile (et non
  `chmod +x` seul, qui, sur un fichier copié en `rw-r-----`, donne `rwxr-x--x`).
- **Piège associé** : invisible en test `docker-compose` local (lancé en `root`, qui lit tout) —
  révélé uniquement via le plugin, qui lance en utilisateur non privilégié. **Toujours tester
  dans les mêmes conditions que la prod (même USER).**

### 1.4 « Port is already allocated »
- **Symptôme** : impossible de lancer une nouvelle instance, le port est pris.
- **Cause** : conteneurs « zombies » d'anciennes instances non nettoyées.
- **Correction** : `sudo docker rm -f <id>` sur les conteneurs orphelins. ⚠️ Ne jamais faire
  un `docker rm -f` large par `ancestor` sans vérifier : on risque de tuer une instance
  **live** en cours d'utilisation.

## 2. Réseau & accès

### 2.1 Service injoignable sur `127.0.0.1`
- **Symptôme** : connexion refusée sur `127.0.0.1:<port>` alors que le conteneur tourne.
- **Cause** : Docker publie les ports sur l'**IP Tailscale** de la VM (`100.118.132.76`),
  pas sur la boucle locale.
- **Correction** : se connecter via l'IP du tailnet (`100.118.132.76:<port>`).

### 2.2 Mauvais port d'accès documenté
- **Symptôme** : la doc envoyait les joueurs sur `http://<ip>:8000`, qui ne répond pas.
- **Cause** : `8000` est le port **interne** de gunicorn (`127.0.0.1:8000`) ; l'accès réel
  passe par **Apache** (port 80) puis en **HTTPS**.
- **Correction** : documenter `https://ctf-rootmeup.tail8588a8.ts.net/`.

## 3. Sécurité

### 3.1 Flags en clair dans un dépôt public
- **Symptôme** : les flags étaient committés en dur dans certains challenges, alors que le
  dépôt est public (pour le jury).
- **Cause** : valeurs sensibles versionnées.
- **Correction** : mécanisme de **rotation** — les flags sont lus au build depuis
  `setup/challenge.env` (**gitignoré**, présent uniquement sur le serveur) ; un
  `challenge.env.example` sert de modèle. Le flag n'apparaît jamais dans le dépôt.

### 3.2 Accès en clair (HTTP)
- **Symptôme** : CTFd et Grafana servis en HTTP simple.
- **Correction** : **HTTPS via Tailscale** (TLS terminé par Tailscale, certificats
  Let's Encrypt automatiques) pour CTFd et Grafana. Grafana n'écoute plus qu'en
  `127.0.0.1:3000` (port en clair fermé) ; l'ancien `http://` de CTFd redirige en 301.

## 4. Contenu & cohérence des challenges

### 4.1 Mauvais format de flag dans les guides joueurs
- **Symptôme** : des guides annonçaient un format (`FLAG{...}`, `MERIDIAN{...}`) différent du
  format réellement configuré dans CTFd → soumissions rejetées côté joueur.
- **Cause** : guides rédigés avant fixation des flags, jamais resynchronisés.
- **Correction** : format aligné sur la base CTFd (majoritairement `RootMeUp{...}`, plus
  quelques cas `FLAG{...}`, `RM{...}`, `blue{...}` et valeurs brutes selon le challenge).

### 4.2 Solution de référence désynchronisée du build
- **Symptôme** : l'exploit de référence échouait sur l'instance déployée (entrée rejetée),
  alors que le binaire fonctionnait.
- **Cause** : une valeur codée en dur dans l'exploit ne correspondait plus à celle cuite dans
  l'image (issue de `challenge.env` au build).
- **Correction** : resynchronisation exploit/solution avec la valeur réellement buildée, +
  commentaire mainteneur rappelant de garder les deux alignés en cas de rotation.

### 4.3 Challenge dépendant d'outils installés côté joueur
- **Symptôme** : un challenge forensics nécessitait que le joueur installe des outils en local
  (plateforme non « stand-alone »).
- **Correction** : refonte en **boîte d'analyse SSH** — le joueur reçoit une instance avec le
  dump et les outils déjà présents (`Start Instance` → `ssh …`), sur le modèle de pwn.college.

## 5. Git & workflow d'équipe

### 5.1 Un merge a effacé des challenges
- **Symptôme** : après le merge d'une branche, des challenges avaient disparu de `main`.
- **Cause** : branche **« challenge-only »** ne contenant qu'un seul challenge (les autres
  dossiers supprimés). Au merge, git a propagé ces suppressions sur `main`. « Able to merge »
  (vert) signifie *pas de conflit*, pas *sans danger* — une suppression n'est pas un conflit.
- **Correction & règle** : **1 challenge = 1 branche, mais la branche est une copie complète
  du dépôt** ; on ne modifie **que** son propre dossier `challenges/N-…`. Avant tout merge,
  vérifier l'onglet **« Files changed »** : il ne doit lister que les fichiers de son challenge.
  (Voir [`DEPLOIEMENT.md`](DEPLOIEMENT.md) §2.)

## Enseignements transverses

- **Tester dans les conditions de production** (même utilisateur, même lanceur) : plusieurs
  bugs n'apparaissaient qu'via le plugin, pas en `docker-compose` local.
- **Séparer secret et code** : flags/valeurs sensibles hors du dépôt (`challenge.env`),
  reconstruits au build.
- **Garder la doc synchronisée avec le déploiement réel** : formats de flags, ports, URLs —
  vérifiés contre la base CTFd et l'infra, pas contre les intentions initiales.

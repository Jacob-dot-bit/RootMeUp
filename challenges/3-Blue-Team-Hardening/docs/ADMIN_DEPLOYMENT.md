# 🛠️ Guide Admin & Déploiement — Hardening

> ⚠️ Contient les flags et la logique interne. Ne pas distribuer aux joueurs.

## 1. Architecture
Deux composants **séparés** :

**A. Le conteneur du joueur** (image Docker, build multi-stage) — ne contient **AUCUN flag** :
- **Stage builder** : compile `audit/checker.c` en binaire (`gcc -O2 -s`) ;
- `setup/harden_setup.sh` déploie l'**état vulnérable** au *build* (10 mauvaises configs, difficulté croissante) ;
- **ttyd** sert un **terminal web** sur le **port 8000**, session `analyst` (sudo) ;
- `/opt/audit/checker` (commande `audit`) affiche **uniquement la progression** (fait / à corriger), **jamais de flag**.

**B. Le valideur côté serveur** `grader/grade.py` — tourne sur l'**hôte CTFd / poste admin**, **hors** du conteneur. C'est **lui seul** qui détient les flags. Il inspecte l'état d'une instance (en local pour les tests, ou à distance via SSH) et ne délivre un flag qu'une fois le correctif réellement appliqué.

Conséquence : le joueur, même root sur son instance, n'a aucun flag à voler ni à reverse-engineerer — **ils ne sont pas dans la machine**. Démarrage en quelques secondes.

## 2. Build & test local
```bash
cd 3-Blue-Team-Hardening
docker build -t nw-hardening:latest .
docker run --rm -p 8000:8000 nw-hardening:latest
# Ouvrir http://localhost:8000  -> terminal web -> taper : audit
```

### Tester la validation SANS Docker (nécessite `python3`)
```bash
bash solution/verify_hardening.sh
# Exécute grader/grade.py sur un arbre de test : 0/10 (avant) puis 10/10 (après)
```

## 3. Intégration CTFd (CTFdDockerContainersPlugin)

### 3.1 Publier l'image
```bash
docker tag nw-hardening:latest <registry>/nw-hardening:latest
docker push <registry>/nw-hardening:latest
```

### 3.2 Question 1 = challenge « conteneur »
Admin → Challenges → + → type **container** :
- **Image** : `<registry>/nw-hardening:latest`
- **Port** : `8000`
- Flag : celui de la **Q1** (`ctfd/flags.txt`).

C'est ce challenge qui affiche **Start Instance**. La même instance sert les 10
questions (le joueur durcit le serveur et récupère les flags au fur et à mesure).

### 3.3 Questions 2 → 10 (déblocage progressif)
9 challenges **standard**, un par question :
- énoncé depuis `ctfd/challenges.yml` ;
- flag depuis `ctfd/flags.txt` (static, **case-sensitive**) ;
- **Requirements / Prérequis** = la question précédente.

→ Progression **flag par flag** visible dans CTFd.

## 4. Barème conseillé (difficulté croissante)
| Q | Difficulté | Points |
|---|------------|--------|
| 1 | facile | 50 |
| 2 | facile | 50 |
| 3 | facile | 75 |
| 4 | moyen | 100 |
| 5 | moyen | 100 |
| 6 | moyen | 125 |
| 7 | difficile | 150 |
| 8 | difficile | 175 |
| 9 | expert | 225 |
| 10 | expert | 250 |

Les énoncés Q9/Q10 ne donnent **aucun indice** (comme la commande `audit`).

## 5. Anti-triche — modèle retenu
Question : **peut-on obtenir un flag sans durcir la machine, même en reversant ?**
Réponse avec ce modèle : **non**, parce que les flags **ne sont pas dans le
conteneur du joueur**.

- Le binaire `checker` embarqué ne contient **aucun flag** (vérifié : `strings`
  ne renvoie rien). Le reverser ne donne donc rien à extraire.
- Les flags vivent **uniquement** dans `grader/grade.py`, exécuté côté serveur,
  là où le joueur n'a **aucun** accès (il n'est pas root sur l'hôte CTFd).
- Le grader ne délivre un flag que si l'état de l'instance est **réellement
  conforme** (permissions/config/absence de fichier). « Valider » = appliquer le
  vrai correctif.

C'est le principe des CTF défensifs : **on ne cache pas un secret à quelqu'un qui
contrôle la machine — on met le secret ailleurs.** La validation étant hors du
périmètre du joueur, ni `cat`, ni `strings`, ni gdb/objdump ne permettent de
récupérer un flag.

## 6. Récupération des flags par le joueur (service `getflag`)
Modèle principal : **le joueur tape `getflag <N>` dans le terminal**, ce qui
interroge le **service de validation** hébergé côté serveur ; le service
inspecte lui-même l'instance et renvoie le flag si la faille est corrigée. Le
joueur le **saisit ensuite dans CTFd** (flux jeopardy classique). Aucun flag
n'existe dans le conteneur.

### 6.1 Lancer le service de validation (sur l'hôte Docker)
```bash
pip install flask
python3 grader/grade_server.py --port 9000       # prod : inspection via `docker exec`
```
Le service (`grade_server.py`) :
- identifie le conteneur appelant par son **IP source** (`docker inspect`) → un
  joueur ne peut réclamer que les flags de **sa propre** instance ;
- inspecte l'état **lui-même** via `docker exec` (il ne fait jamais confiance au
  client) ;
- détient les flags (via `grader/checks.py`) — ils ne sont **jamais** dans l'image.

Prérequis : l'hôte exécutant le service a accès à la socket Docker, et les
instances peuvent le joindre à l'URL `GRADER_URL` (par défaut
`http://host.docker.internal:9000`). Adaptez-la au lancement du conteneur :
```bash
docker run -e GRADER_URL="http://<ip_hote>:9000" -p 8000:8000 nw-hardening:latest
```

### 6.2 Côté joueur
```bash
audit             # progression (fait / à corriger)
sudo ...          # je corrige une faille
getflag 3         # -> le serveur valide et me renvoie le flag de la tâche 3
```

### 6.3 Alternatives (sans le service getflag)
- **Correction manuelle / soutenance** : l'admin lit les flags gagnés d'une équipe
  ```bash
  python3 grader/grade.py --ssh root@<ip_instance> -p <port>
  python3 grader/grade.py --ssh ... --task 3      # un seul flag
  ```
- **Award auto** : un cron appelle `grade.py --score-only` par instance et marque
  les challenges résolus via l'API CTFd.

### 6.4 Test en local sans Docker (mode dev)
```bash
python3 grader/grade_server.py --port 9000 --dev-target /chemin/rootfs &
GRADER_URL=http://127.0.0.1:9000 bash setup/getflag 1
```

## 7. Dépannage
| Symptôme | Cause | Solution |
|----------|-------|----------|
| Terminal web ne charge pas | ttyd non démarré | `docker logs`, vérifier le port 8000 |
| `audit` demande un mot de passe | sudoers analyst absent | vérifier `/etc/sudoers.d/00-analyst` (NOPASSWD) |
| Un contrôle ne passe pas en [OK] | correctif incomplet | relire l'indice `[À CORRIGER]`, vérifier avec `stat`/`grep` |
| Grader renvoie 0/10 en SSH | accès/chemins | tester `--target` en local, vérifier les droits SSH |
| Build échoue au download ttyd | pas de réseau au build | pré-télécharger `ttyd.x86_64` et `COPY` le binaire |
| Flags refusés dans CTFd | casse/espaces | flags exacts, format `NW{...}` |

## 8. Personnaliser
Modifiez les valeurs dans `setup/harden_setup.sh` (secrets, comptes, services),
les contrôles dans `audit/checker.c` (auto-évaluation joueur) **et** les flags +
contrôles dans `grader/grade.py` (validation serveur, source de vérité des
flags). Reconstruisez l'image et re-testez avec `solution/verify_hardening.sh`.
⚠️ Gardez `checker.c` et `grade.py` cohérents (mêmes 10 contrôles).

*Blue Team CTF – Lucas – ESGI Projet Annuel 2026*

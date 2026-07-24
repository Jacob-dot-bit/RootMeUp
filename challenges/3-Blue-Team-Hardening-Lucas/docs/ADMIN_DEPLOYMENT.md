# 🛠️ Guide Admin & Déploiement — Hardening

> ⚠️ Contient les flags et la logique interne. Ne pas distribuer aux joueurs.

## 1. Architecture
**Un seul conteneur, autonome** (build multi-stage). **Rien à faire tourner côté serveur.**
- **Stage builder** : compile `audit/checker.c` et `audit/getflag.c` en binaires (`gcc -O2 -s`, symboles supprimés).
- `setup/harden_setup.sh` déploie l'**état vulnérable** au *build* (10 mauvaises configs, difficulté croissante).
- **ttyd** sert un **terminal web** sur le **port 8000**, session `analyst` (sudo).
- Commande **`audit`** (`/opt/audit/checker`) : affiche la **progression** (fait / à corriger), **jamais de flag**.
- Commande **`getflag N`** (`/opt/audit/getflag`) : re-vérifie que la faille N est réellement corrigée, et **seulement dans ce cas** décode et affiche le flag N. Les flags sont **XOR-obfusqués** dans le binaire compilé (aucun flag en clair).

Démarrage en quelques secondes. Le joueur soumet ensuite le flag dans CTFd (flux jeopardy classique).

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

## 5. Anti-triche — honnêteté sur les limites
Question : **peut-on obtenir un flag sans durcir, même en reversant ?**

Ce qui est bloqué :
- **Aucun flag en clair** dans l'image : ils sont XOR-obfusqués dans le binaire
  `getflag` compilé et strippé. `cat` / `strings` ne renvoient **rien** (vérifié).
- `getflag N` ne décode le flag que si la faille N est **réellement corrigée**.
  « Obtenir » un flag = appliquer le vrai correctif.

La limite honnête à assumer devant le jury : le joueur est **root sur son
instance**, ce qui est **indispensable pour durcir un système**. Faire tourner
un valideur **hors** de sa portée demanderait un composant serveur (accès à la
socket Docker de l'hôte CTFd), ce qui n'est pas possible dans cet environnement.
Sans ce composant, un joueur **expert** pourrait désosser le binaire (gdb /
objdump) pour extraire les flags. C'est une **propriété fondamentale** : on ne
peut pas cacher un secret à quelqu'un qui contrôle la machine.

En pratique c'est un **très bon niveau pour un CTF** — supérieur à la norme, où
les flags sont souvent en clair dans le conteneur / les logs / les artefacts
(comme dans la plupart des autres challenges). La triche « facile » (cat/strings)
est bloquée, et récupérer un flag exige soit de **durcir réellement**, soit de
faire du **reverse engineering** (une compétence en soi). Pour la notation, le
**rapport** (`report/`) et la **démo en soutenance** restent la preuve du travail.

## 6. Vérification admin (optionnelle, hors conteneur)
Pour contrôler l'état d'une instance sans passer par `getflag`, un outil CLI est
fourni (il n'est **pas** embarqué dans l'image) :
```bash
python3 grader/grade.py --ssh root@<ip_instance> -p <port>   # les 10 tâches
python3 grader/grade.py --ssh ... --task 3                   # une seule
python3 grader/grade.py --target /chemin/rootfs              # sur un FS local
```

## 7. Dépannage
| Symptôme | Cause | Solution |
|----------|-------|----------|
| Terminal web ne charge pas | ttyd non démarré | `docker logs`, vérifier le port 8000 |
| `audit` demande un mot de passe | sudoers analyst absent | vérifier `/etc/sudoers.d/00-analyst` (NOPASSWD) |
| `getflag N` dit « pas encore corrigée » | correctif incomplet | relire `audit`, vérifier avec `stat`/`grep` |
| `getflag` / `audit` demande un mot de passe | sudoers analyst absent | vérifier `/etc/sudoers.d/00-analyst` (NOPASSWD) |
| Build échoue au download ttyd | pas de réseau au build | pré-télécharger `ttyd.x86_64` et `COPY` le binaire |
| Flags refusés dans CTFd | casse/espaces | flags exacts, format `RootMeUp{...}` |

## 8. Personnaliser
Modifiez les valeurs dans `setup/harden_setup.sh` (secrets, comptes, services),
puis les contrôles dans `audit/checker.c` (progression) **et** `audit/getflag.c`
(délivrance des flags — c'est là que sont les flags obfusqués), en les gardant
**cohérents** (mêmes 10 contrôles). Le module `grader/checks.py` doit suivre si
vous utilisez l'outil de vérification admin. Reconstruisez l'image et re-testez
avec `solution/verify_hardening.sh`.

> Pour régénérer les tableaux XOR de `getflag.c` après changement des flags :
> `python3` → `[ord(c)^0x5A for c in "RootMeUp{...}"]` (voir en-tête du fichier).

*Blue Team CTF – Lucas – ESGI Projet Annuel 2026*

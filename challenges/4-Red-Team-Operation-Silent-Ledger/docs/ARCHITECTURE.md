# Architecture technique

## Pourquoi un seul conteneur (pas de docker-compose multi-hôtes) ?

Le plugin CTFd Docker gère nativement **une image = un bouton = un conteneur**.
Simuler plusieurs "hôtes" internes (jump host / app server / db server) via un
`docker-compose` multi-conteneurs aurait nécessité soit un support compose côté
plugin (non garanti selon la version), soit du Docker-in-Docker en mode
`privileged` (risque opérationnel et sécurité pour un déploiement mutualisé,
fragile en démonstration live). Le choix a été de simuler la **segmentation par
privilège** (comptes systèmes distincts, capabilities, sudo ciblé) plutôt que la
segmentation réseau — ce qui reste un exercice de post-exploitation très réaliste
(le mouvement latéral "inter-comptes" sur un même host est une compétence tout
aussi centrale que le pivot réseau) et beaucoup plus simple à faire tourner de
façon fiable pendant une soutenance.

## Pourquoi pas un vrai socket Docker (`/var/run/docker.sock`) pour F8 ?

Exposer le vrai socket Docker de l'hôte à l'intérieur du conteneur revient à
offrir un accès root sur la machine hôte à quiconque compromet le conteneur —
inacceptable dans un environnement CTFd partagé. À la place, un **daemon interne
original** (`orchestrator.py`) simule un outil de gestion de flotte "maison",
avec une vraie vulnérabilité (désérialisation Python non sécurisée) qui offre la
même sensation pédagogique (exploiter un outil d'administration interne) sans
aucun risque d'évasion réelle vers l'hôte.

## Pourquoi pas de vulnérabilité web ?

Contrainte du projet : éviter le chevauchement avec le challenge d'un collègue
(CTF red sur service web vulnérable). Ce challenge est donc **100% système** :
permissions Unix, cron, SUID, sudo, capabilities, un service interne exposé via
socket UNIX (pas HTTP, pas de navigateur), cryptographie appliquée. Le seul
composant "applicatif" (l'orchestrateur) n'est ni HTTP ni piloté depuis un
navigateur, ce qui le distingue nettement d'un challenge web classique.

## Chaîne de comptes et de privilèges (STRICTEMENT MONOTONE)

```
j.martin        (SSH direct, mot de passe fourni)
  └─ svc_backup (mot de passe dans .bash_history de j.martin)                 [F3]
       └─ r.dubois   (cron EXÉCUTÉ EN TANT QUE r.dubois, script grp-writable) [F4]
            └─ app_agent   (sudo NOPASSWD find -> GTFOBins)                    [F5]
                 └─ svc_orch   (SUID logviewer -> SUID svc_orch, PAS root)     [F6]
                      └─ (capability cap_dac_read_search, lecture seule)       [F7]
                           └─ orchestrator.sock (token + pickle RCE) -> ROOT   [F8]
```

**Principe de conception :** chaque saut mène à **un compte précis**, jamais à
root, jusqu'à la toute dernière étape système (F8). C'est ce qui rend la chaîne
*monotone* et garantit que chaque technique est **obligatoire** :

- Le **cron (F4) tourne en `r.dubois`**, pas en root → saut latéral, pas de RCE root.
- Le **SUID logviewer (F6) est SUID `svc_orch`**, pas root (le binaire fait
  `setreuid(euid,euid)`, jamais `setuid(0)`).
- Le binaire à **capability (F7) est en mode `700`, propriété `svc_orch`** : seul
  `svc_orch` (atteint au F6) peut l'exécuter. C'était le principal défaut de la
  version précédente (`py-agent` en `755` = exécutable par *n'importe qui*, donc
  `j.martin` pouvait lire tous les fichiers `/root` dès le flag 1). On utilise
  `cap_dac_read_search` (**lecture seule**) et non `cap_dac_override` (qui
  permettrait l'écriture de `/etc/passwd`, `/etc/sudoers`… = root).
- Le **flag 8 ne vit qu'en mémoire** de l'orchestrateur : chargé au démarrage
  puis le fichier source est supprimé. La capability F7 (lecture de fichiers)
  ne peut donc pas le récupérer — seule l'exécution de code *dans* le process
  (la désérialisation) le révèle.
- Les **flags 9 et 10 sont protégés par la cryptographie** (zip / GPG) : même
  root, il faut casser le mot de passe et le PIN. Ce sont les seuls secrets qui
  résistent légitimement à root, et ils sont donc placés en fin de chaîne.

> ⚠️ **Contrainte runtime :** le flag 7 dépend de `cap_dac_read_search`, qui ne
> fait **pas** partie des capabilities Docker par défaut. L'instance doit être
> lancée avec `--cap-add DAC_READ_SEARCH` (voir CTFD_SETUP.md). Cette capability
> est en lecture seule : elle ne peut pas être détournée pour obtenir root.

## Reproductibilité des flags

Les flags sont statiques (mêmes valeurs à chaque build), ce qui est acceptable
puisque **chaque équipe reçoit sa propre instance isolée** détruite après usage
(garantie du plugin CTFd Docker : un conteneur par équipe/joueur, réseau non
partagé). Il n'y a donc pas de risque de fuite d'un flag d'une équipe à l'autre.

Si vous préférez des flags uniques par instance (protection contre le partage de
flags entre équipes qui compareraient leurs copies d'écran), il est possible
d'ajouter un script d'entrypoint qui régénère les flags à partir d'une variable
d'environnement injectée par le plugin (souvent une variable type
`TEAM_ID`/`CHALLENGE_ID`) au démarrage du conteneur — non implémenté ici pour
garder le build reproductible et simple à corriger, mais c'est une extension
naturelle si le format de compétition l'exige.

## Durcissement du déploiement (hôte partagé)

Le joueur obtient root **dans le conteneur** (au F8) : c'est le but. L'isolation
repose donc sur le conteneur, à durcir au niveau du run / du plugin :

- **Aucun `--privileged`, pas de montage de `/var/run/docker.sock`** (F8 utilise
  un faux orchestrateur, pas le vrai Docker) → pas d'évasion vers l'hôte.
- Ajouter **uniquement** `--cap-add DAC_READ_SEARCH` (nécessaire au F7) ; ne rien
  ajouter d'autre.
- **Réseau isolé sans accès Internet** (bridge `--internal`) : rien n'en a besoin,
  et une instance compromise ne peut pas servir de relais.
- **Limites de ressources** : `--pids-limit 512`, `--memory 512m`, `--cpus 1`
  pour éviter qu'une instance rootée ne sature l'hôte.
- Garder le **noyau de l'hôte à jour** (seul vecteur résiduel = évasion via faille
  kernel, indépendant du challenge).

## Fichiers du projet

```
4-Red-Team-Operation-Silent-Ledger/
├── Dockerfile                # build multi-stage (builder / secrets / final)
├── challenge/                # tout ce qui est copié dans l'image
│   ├── logviewer.c           # SUID svc_orch, injection de commande (F6)
│   ├── orchestrator.py       # daemon interne, désérialisation (F8), flag8 en mémoire
│   ├── entrypoint.sh
│   ├── cleanup.sh            # script cron inscriptible par svc_backup (F4)
│   ├── cron_meridian         # /etc/cron.d/meridian (job exécuté en r.dubois)
│   ├── sudoers_rdubois       # /etc/sudoers.d/r_dubois : r.dubois->app_agent (F5)
│   └── flag*.txt, *.bak, ... # contenu et leurres placés dans l'image
├── ctfd/
│   ├── CTFd_a_copier.md      # textes prêts à coller (1 par challenge)
│   └── flags.txt             # récap des 10 flags (admin only)
└── docs/
    ├── SCENARIO_JOUEUR.md    # brief joueur
    ├── SOLUTION_WRITEUP.md   # correction complète
    ├── CTFD_SETUP.md         # configuration CTFd + plugin (+ --cap-add)
    └── ARCHITECTURE.md       # ce fichier
```

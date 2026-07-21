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

## Chaîne de comptes et de privilèges

```
j.martin        (SSH direct, mot de passe fourni)
  └─ svc_backup (mot de passe dans .bash_history de j.martin)
       └─ [cron root inscriptible par le groupe svc_backup]
            └─ r.dubois   (mot de passe exfiltré via le cron)
                 ├─ SUID logviewer (groupe analysts) -> lecture/exec root
                 └─ sudo NOPASSWD find -> app_agent
                      └─ py-agent (cap_dac_read_search) -> lecture arbitraire
                           └─ orchestrator.sock (token + pickle RCE) -> root
```

Chaque saut change de compte Unix ; aucun ne donne un shell root interactif
"gratuit" avant l'étape 8, ce qui garantit que les 7 premières étapes se résolvent
uniquement par de l'énumération et de l'abus de permissions — pas par accident.

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

## Fichiers du projet

```
4-Red-Team-Operation-Silent-Ledger/
├── Dockerfile                # build multi-stage (builder / secrets / final)
├── challenge/                    # tout ce qui est copié dans l'image
│   ├── logviewer.c           # binaire SUID vulnérable (F5)
│   ├── orchestrator.py       # daemon interne, désérialisation (F8)
│   ├── entrypoint.sh
│   ├── cleanup.sh            # script cron inscriptible (F4)
│   ├── cron_meridian         # /etc/cron.d/meridian
│   ├── sudoers_rdubois       # /etc/sudoers.d/r_dubois (F6)
│   └── flag*.txt, *.bak, ... # contenu et leurres placés dans l'image
└── docs/
    ├── SCENARIO_JOUEUR.md    # textes à coller dans CTFd
    ├── SOLUTION_WRITEUP.md   # correction complète (ce document jumeau)
    ├── CTFD_SETUP.md         # configuration CTFd + plugin
    └── ARCHITECTURE.md        # ce fichier
```

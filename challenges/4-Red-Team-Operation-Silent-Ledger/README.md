# Operation SILENT LEDGER — CTF Red Team (post-exploitation Linux)

Challenge CTF pour projet annuel — 10 flags progressifs sur une seule instance
Docker, destiné à CTFd + `CTFdDockerContainersPlugin`.

Scénario : après un accès initial déjà obtenu (identifiants SSH d'un stagiaire),
le joueur mène une chaîne complète de post-exploitation Linux jusqu'à
l'exfiltration finale — énumération, récolte d'identifiants, cron, SUID,
sudo/GTFOBins, capabilities, exploitation d'un outil interne (désérialisation),
cassage de mots de passe hors-ligne, chiffrement GPG.

## Démarrage rapide

> ⚠️ L'instance DOIT être lancée avec `--cap-add DAC_READ_SEARCH` (nécessaire au
> flag 7 ; cette capability est absente du set Docker par défaut). Ne rien ajouter
> d'autre (pas de `--privileged`).

```bash
docker build -t meridian-silent-ledger .
docker run -d -p 2222:22 --cap-add DAC_READ_SEARCH \
  --pids-limit 512 --memory 512m --name silent-ledger meridian-silent-ledger
ssh j.martin@localhost -p 2222   # mot de passe : Welcome2024!
```

## Documentation

- [`docs/SCENARIO_JOUEUR.md`](docs/SCENARIO_JOUEUR.md) — briefing et textes à
  coller dans CTFd (un par challenge), barème de points.
- [`docs/SOLUTION_WRITEUP.md`](docs/SOLUTION_WRITEUP.md) — **correction complète**,
  commande par commande, pour les 10 flags.
- [`docs/CTFD_SETUP.md`](docs/CTFD_SETUP.md) — configuration pas à pas de CTFd et
  du plugin Docker (image, ports, prérequis pour forcer l'ordre chronologique).
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — choix de conception et
  justification technique (utile pour la soutenance).

## Barème (1650 points au total)

| # | Challenge | Technique | Points |
|---|-----------|-----------|-------:|
| 1 | Premiers pas | Reconnaissance | 50 |
| 2 | Fouille de printemps | Énumération filesystem | 75 |
| 3 | Mauvaise mémoire | Récolte d'identifiants | 100 |
| 4 | Tâche planifiée | Cron privesc | 125 |
| 5 | Délégation hasardeuse | Sudo misconfig (GTFOBins) | 150 |
| 6 | Journaux confidentiels | SUID / injection de commande | 175 |
| 7 | Pouvoirs spéciaux | Capabilities Linux | 200 |
| 8 | L'orchestrateur | Désérialisation non sécurisée (RCE root) | 225 |
| 9 | Le coffre | Cassage de mot de passe (zip) | 250 |
| 10 | Silent Ledger | Cassage PIN + déchiffrement GPG | 300 |

## Statut

- [x] Dockerfile + tous les artefacts du challenge écrits
- [ ] Build & test end-to-end (Docker Desktop indisponible dans l'environnement
      où ce projet a été généré — à faire sur ta machine, voir ci-dessous)
- [ ] Intégration CTFd effective

### Comment tester avant intégration CTFd

```bash
docker build -t meridian-silent-ledger .
docker run -d -p 2222:22 --cap-add DAC_READ_SEARCH --name test-ledger meridian-silent-ledger
ssh j.martin@localhost -p 2222
# Welcome2024!
# ... suivre docs/SOLUTION_WRITEUP.md flag par flag jusqu'au 10
docker rm -f test-ledger
```

> Chaîne v2 (durcie) : privesc strictement monotone (un compte par étape, root
> seulement au flag 8), `py-agent` restreint à `svc_orch`, flag 8 en mémoire.
> Voir `docs/ARCHITECTURE.md`.

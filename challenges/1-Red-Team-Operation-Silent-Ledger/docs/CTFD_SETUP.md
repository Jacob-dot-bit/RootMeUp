# Intégration dans CTFd + CTFdDockerContainersPlugin

## 1. Build & publication de l'image

```bash
cd challenges/1-Red-Team-Operation-Silent-Ledger
docker build -t registry.local/meridian-silent-ledger:latest .

# si votre CTFd/plugin tire les images depuis un registre privé :
docker push registry.local/meridian-silent-ledger:latest

# si le plugin utilise le même daemon Docker que CTFd (setup local/mono-hôte) :
# rien à pousser, l'image est déjà visible par `docker images`
```

⚠️ **Ne poussez jamais l'image en la reconstruisant avec `--cache-from` un cache
partagé/public** : le stage intermédiaire `secrets` contient brièvement les flags
en clair avant chiffrement. Le multi-stage build les exclut de l'image finale, mais
un cache exporté (`buildx --cache-to`) pourrait les réintroduire. En usage normal
(`docker build` local) il n'y a aucun risque : seul le stage final est exporté.

## 2. Configuration du plugin (CTFdDockerContainersPlugin)

Dans l'admin CTFd → onglet du plugin Docker :

1. **Docker Host** : renseignez le socket/host du daemon Docker qui exécutera les
   instances (ex : `unix:///var/run/docker.sock` en local, ou une URL TCP+TLS pour
   un hôte distant).
2. **Add Image** : ajoutez `registry.local/meridian-silent-ledger:latest` à la liste
   des images autorisées.
3. Vérifiez que le réseau Docker utilisé pour ces instances **n'a pas d'accès
   sortant à Internet** (bridge isolé / `--internal`). Rien dans ce challenge n'en
   a besoin, et ça évite qu'une instance compromise serve de relais.

## 3. Création des challenges (10 + 1 point d'entrée)

Créez une catégorie unique, par exemple `Red Team — Silent Ledger`.

### Challenge "Premiers pas" (F1) — celui qui porte le bouton Docker

- Type : **Docker** (le type fourni par le plugin, pas "standard")
- Image : `registry.local/meridian-silent-ledger:latest`
- Port exposé : `22/tcp`
- Description : voir `SCENARIO_JOUEUR.md` section 1
- Points : 50 (dynamique ou statique selon votre préférence — voir §5)
- Flag : `MERIDIAN{f1rst_st3ps_1nt0_th3_n3tw0rk_3a1c9d}`

C'est le **seul** challenge avec un bouton "Start Instance". Les 9 suivants sont
des challenges **standards** (flag texte) : le joueur reste sur l'instance déjà
lancée pour les résoudre tous.

### Challenges 2 à 10 — type "standard"

Pour chacun, en plus du texte (voir `SCENARIO_JOUEUR.md`) :

| # | Nom             | Points | Flag                                                        |
|---|------------------|-------:|--------------------------------------------------------------|
| 2 | Fouille de printemps | 75 | `MERIDIAN{h1dd3n_1n_pla1n_s1ght_7b2e41}` |
| 3 | Mauvaise mémoire | 100 | `MERIDIAN{h1st0ry_r3p3ats_1ts3lf_c48a02}` |
| 4 | Tâche planifiée | 125 | `MERIDIAN{cr0n_j0bs_ar3_g0ld_9d17f3}` |
| 5 | Journaux confidentiels | 150 | `MERIDIAN{su1d_b1nar13s_l13_0ft3n_2f6b58}` |
| 6 | Délégation hasardeuse | 175 | `MERIDIAN{sud0_m1sc0nf1g_str1k3s_ag41n_e0a934}` |
| 7 | Pouvoirs spéciaux | 200 | `MERIDIAN{cap4bilit13s_ar3_p0w3r_5c2d71}` |
| 8 | L'orchestrateur | 225 | `MERIDIAN{0rch3str4t0r_pwn3d_88af0d}` |
| 9 | Le coffre | 250 | `MERIDIAN{cr4ck3d_th3_v4ult_1e39b6}` |
| 10 | Silent Ledger | 300 | `MERIDIAN{0p3ration_s1l3nt_l3dg3r_c0mpl3t3_f4a217}` |

> Vérifiez le flag exact de F5 dans `challenge/flag5.txt` après build — pensez à le
> recopier ici. (Il est reproduit dans `SOLUTION_WRITEUP.md`.)

## 4. Forcer l'ordre chronologique avec les prérequis CTFd

CTFd permet de conditionner l'apparition d'un challenge à la résolution d'un autre
(onglet **Requirements** dans l'édition d'un challenge). Configurez une chaîne
strictement linéaire :

```
F1 → (requiert F1) F2 → (requiert F2) F3 → ... → (requiert F9) F10
```

Concrètement, dans le challenge F2 : Requirements = [F1]. Dans F3 : Requirements =
[F2]. Etc. Ainsi les joueurs ne voient jamais la tuile "Le coffre" avant d'avoir
résolu "L'orchestrateur" — cela matérialise la progression chronologique demandée,
même si techniquement rien n'empêche un joueur curieux de fouiller la machine dans
le désordre (ce qui est réaliste pour un vrai engagement red team).

Option "Anonymize requirements" : laissez décoché pour que le joueur voie qu'il
reste des challenges à débloquer (motivant), sinon la tuile est invisible tant que
non débloquée.

## 5. Points : statique ou dynamique ?

Recommandation : **points statiques** (les valeurs du tableau ci-dessus). Un
barème dynamique (qui décroît avec le nombre de résolutions) n'a pas beaucoup de
sens ici puisque chaque joueur/équipe a sa propre instance isolée et que
l'objectif pédagogique est la progression individuelle, pas la compétition sur la
rareté d'un flag.

## 6. Bornes de temps / nettoyage des instances

Réglez dans le plugin :
- **Durée de vie max d'une instance** : 2 à 3 h (le temps de faire les 10 étapes
  confortablement en environnement de soutenance/évaluation) ; ajustez selon votre
  format d'épreuve.
- **Limite d'instances simultanées par équipe** : 1 (le challenge est conçu pour
  une seule instance à la fois — relancer en efface la progression sur la machine,
  mais pas les flags déjà soumis dans CTFd, qui restent acquis).

## 7. Test avant mise en prod

Avant l'épreuve, lancez vous-même une instance depuis CTFd (pas juste `docker run`
en local) pour vérifier bout en bout : port mapping correct, bannière SSH visible,
et les 10 flags atteignables via le chemin décrit dans `SOLUTION_WRITEUP.md`.

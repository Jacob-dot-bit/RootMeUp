# Plan du premier commit

## Objectif
Documenter ce que doit contenir le commit initial open source (projet d'école), avec une structure claire et sans secrets.

## Structure cible du repo
- README.md
- LICENSE (MIT)
- docs/
  - architecture.md
  - diagram.png (schéma)
  - commit-plan.md (ce fichier)
- .gitignore (à ajouter pour exclure .env, fichiers temporaires)
- .env.example (optionnel, sans secrets)

## Contenu attendu dans le premier commit
- README.md : présentation, prérequis, installation, démarrage, accès, challenges, bonnes pratiques, lien vers l'architecture.
- docs/architecture.md : description des composants, flux réseau, sécurité, exploitation, pistes d'amélioration + schéma.
- LICENSE : texte MIT.
- .gitignore : ignorer `.env`, `*.log`, `__pycache__/`, `node_modules/` si présent, et toute archive ou build.
- (Optionnel) .env.example : variables clés pour CTFd et les challenges, sans valeurs sensibles.

## Ce qui ne doit pas être committé
- Fichiers `.env` réels (secrets, flags).
- Dumps de base de données, archives, builds ou images de conteneurs.
- Logs et artefacts temporaires.

## Suggestion de message de commit
```
git add README.md LICENSE docs .gitignore .env.example
git commit -m "chore: init public release"
```

## Étapes suivantes après le premier commit
- Ajouter les docker-compose et/ou manifestes d'orchestration.
- Renseigner un `.env.example` plus complet si besoin.
- Ajouter un guide d'exploitation (sauvegardes/restauration, rotation de flags, supervision).

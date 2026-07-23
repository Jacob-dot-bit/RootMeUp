# Guide de déploiement — Challenge Red Team « NEXUS Internal Portal »

Challenge offensif crypto / logique applicative. Service web autonome, une seule
image Docker, lancé par le plugin containers de CTFd (comme le challenge ELK).

## Structure du projet

```
ctf-crypto-portal/
├── Dockerfile
├── app/
│   ├── app.py              ← service Flask vulnérable (10 flags)
│   ├── requirements.txt
│   └── templates/
│       └── index.html
├── WALKTHROUGH.md          ← corrigé (à NE PAS livrer aux joueurs)
└── GUIDE_DEPLOIEMENT.md
```

## 1. Build de l'image (sur la VM)

```bash
cd /srv/ctf-challenges/rootmeup/challenges/ctf-crypto-portal
docker build -t rootmeup/rt2-crypto-portal:1.0 .
docker tag  rootmeup/rt2-crypto-portal:1.0 rootmeup/rt2-crypto-portal:latest
docker images | grep crypto-portal
```

## 2. Test local avant mise en CTFd

```bash
docker run --rm -p 8080:8080 rootmeup/rt2-crypto-portal:1.0
# dans un autre terminal :
curl http://127.0.0.1:8080/healthz          # -> ok
curl http://127.0.0.1:8080/internal/dev-notes
```

## 3. Création du challenge dans CTFd

Admin → Challenges → New → type **container** :

| Champ | Valeur |
|---|---|
| Name | NEXUS Internal Portal |
| Docker Image | `rootmeup/rt2-crypto-portal:1.0` |
| Port | `8080` |
| Connection Info | `http://{HOST}:{PORT}` (champ NON vide obligatoire — sinon pas de bouton Start Instance) |
| Docker Assignment | team |
| Max Memory | 256 (léger, contrairement à l'ELK) |

Puis ajouter les 10 flags (voir WALKTHROUGH.md), passer le challenge en **visible**.

> Rappel du couplage plugin/thème : le bouton « Start an Instance » n'apparaît
> que si le champ **Connection Info** du challenge est renseigné.

## 4. Configuration des flags dans CTFd

Créer 10 flags **statiques**. Pour les flags contenant des caractères spéciaux,
cocher *case-insensitive* n'est PAS nécessaire (ils sont en snake_case), mais
vérifier la saisie une fois créés.

Ordre recommandé (scoring croissant, cf. WALKTHROUGH.md) : 50 → 200 pts.

## 5. Personnalisation des secrets (optionnel mais recommandé)

Par défaut, les secrets crypto sont fixés dans le Dockerfile (valeurs faibles
volontaires). Pour éviter que des joueurs partagent les réponses d'une session à
l'autre, tu peux les surcharger au lancement — mais **attention** : le plugin
containers ne permet pas de passer des `-e` par instance. Les valeurs par défaut
sont donc celles utilisées en jeu. Les flags listés dans WALKTHROUGH.md
correspondent à ces valeurs par défaut.

## 6. Ressources

- L'appli tourne en utilisateur non-root dans le conteneur.
- Aucune donnée persistante : `auto_remove=True` du plugin nettoie l'instance.
- Empreinte mémoire ~60-80 Mo : `Max Memory 256` est large.
```

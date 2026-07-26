# Déploiement des challenges — RootMeUp

Guide central : comment déployer / mettre à jour un challenge sur le serveur,
comment sont gérés les flags, et la convention de branches à respecter.

## 1. Vue d'ensemble de l'infra

| Élément | Détail |
|---|---|
| Serveur | VM `ctf-rootmeup` (Debian 13), accès **Tailscale** + SSH |
| Dépôt sur la VM | `/srv/ctf-challenges/RootMeUp` (propriétaire `ctfd` → utiliser `sudo git -C …`) |
| CTFd | venv Python + gunicorn sur `127.0.0.1:8000` ; **Apache** (reverse-proxy) **termine le TLS sur `:443`** (cert Let's Encrypt via `tailscale cert`) → `https://ctf-rootmeup.tail8588a8.ts.net/` |
| Base CTFd | MySQL/MariaDB local (`ctfd`) |
| Instanciation | plugin **CTFdDockerContainersPlugin** : 1 conteneur par équipe/challenge |
| Images | nommées `rootmeup/<code>:1.0` |

## 2. Convention de branches ⚠️ (à lire absolument)

**1 challenge = 1 branche**, MAIS la branche contient **tout le projet** + les modifs
ciblées sur ce challenge. Une branche est une copie complète du dépôt, pas seulement
un challenge.

> ❌ **Ne jamais créer une branche qui ne contient QUE son challenge.** En la mergeant,
> git aligne `main` sur la branche et **supprime tout ce que la branche ne contient pas**
> (les autres challenges, le README, etc.). C'est ce qui a effacé des challenges via le
> commit `8a5a8c3` (réparé ensuite par `be0516d`).

Règles :
1. Créer une branche **depuis `main` à jour** (`git checkout main && git pull && git checkout -b <nom>`).
2. Ne modifier que le dossier de son challenge (`challenges/<N-...>/`).
3. Avant de merger : sur la PR, onglet **« Files changed »** → il ne doit lister que
   des fichiers de **ton** challenge. Sinon, ne pas merger.
4. « Able to merge » (vert) = *pas de conflit*, ça ne veut PAS dire « sans danger » :
   une suppression n'est pas un conflit. Toujours vérifier « Files changed ».

## 3. Flags : rotation & `challenge.env`

Le dépôt est **public** (pour le jury) : les **vrais flags ne doivent jamais y être
committés**. Les challenges concernés lisent leur flag depuis un fichier **gitignoré**.

- Chaque challenge à flag « roté » fournit `setup/challenge.env.example` (modèle).
- On le copie en `setup/challenge.env` (gitignoré) et on y met le **vrai flag roté**
  (une **nouvelle** valeur — les anciens flags restent publics dans l'historique git).
- Le build lit `challenge.env` et cuit le flag dans les artefacts ; le flag n'apparaît
  jamais dans le dépôt.
- `challenge.env` **persiste** sur la VM (survit à `git pull`). ⚠️ `git clean -x` l'effacerait.
- Retrouver un flag à tout moment : `sudo cat …/setup/challenge.env`.
- **Le même flag doit être saisi dans CTFd** (voir §5).

> Challenges utilisant ce mécanisme : `1-Red-Team-Binary-Vault-Jakub`,
> `2-Blue-Team-Memory-Forensics-Jakub`. Les autres ont (encore) leur flag en dur —
> même refactor recommandé.

## 4. Déployer / mettre à jour un challenge

```bash
# 1. mettre le dépôt de la VM à jour
sudo git -C /srv/ctf-challenges/RootMeUp pull

# 2. (challenges à flag) créer/vérifier challenge.env
CH=/srv/ctf-challenges/RootMeUp/challenges/<DOSSIER>
sudo cp "$CH/setup/challenge.env.example" "$CH/setup/challenge.env"   # si absent
sudo nano "$CH/setup/challenge.env"                                   # mettre le vrai flag

# 3. builder l'image (même tag pour que CTFd la retrouve)
sudo docker build -t rootmeup/<CODE>:1.0 "$CH"

# 4. vérifier le flag cuit dans l'image (exemple VAULT)
sudo docker run --rm --entrypoint cat rootmeup/rt1-binary-vault:1.0 \
  /challenge/flag1.txt /challenge/flag2.txt
```

Le plugin CTFd **ne rebuild pas** : il relance l'image déjà construite. Donc le build
se fait **une fois** par challenge/serveur (et à chaque changement de code ou de flag).

## 5. Câbler un challenge dans CTFd (plugin containers)

1. `https://ctf-rootmeup.tail8588a8.ts.net/` → login admin → **Admin Panel → Challenges → Create**.
2. Choisir le type **Container** (fourni par le plugin).
3. Renseigner :
   - **Image** : `rootmeup/<code>:1.0`
   - **Port** interne : voir le tableau §6
   - **Flag** : la valeur de `challenge.env` (type `Static`, *case sensitive*)
4. Config du plugin : **Admin → Containers** (hôte/URL Docker, plage de ports dynamiques).
5. Laisser en `Hidden`, tester **Start Instance** avec un compte non-admin, puis `Visible`.

## 6. Challenges & images

| Challenge (dossier) | Image | Port | Accès joueur |
|---|---|---|---|
| `1-Blue-Team-Phishing-ELK-Sarah` | `rootmeup/bt1-phishing-elk:1.0` | `5601` | HTTP (Kibana) |
| `2-Blue-Team-Memory-Forensics-Jakub` | `rootmeup/bt2-memory-forensics:1.0` | `22` | SSH (`analyst`/`forensics`) — boîte d'analyse, dump + outils dedans |
| `1-Red-Team-Binary-Vault-Jakub` | `rootmeup/rt1-binary-vault:1.0` | `22` | SSH (`hacker`/`vault9`) — boîte stand-alone : binaire + outils (gdb, objdump, pwntools) + service local `nc localhost 9003` |
| `2-Red-Team-Operation-Silent-Ledger-Lucas` | `rootmeup/rt2-silent-ledger:1.0` | `22` | SSH / service |
| `3-Red-Team-Nexus-Cipher-Sarah` | `rootmeup/rt3-ciphers-nexus:1.0` | `8080` | HTTP (API) |
| `3-Blue-Team-Hardening-Lucas` | *(image à confirmer)* | `8000` | SSH / durcissement |
| `4-Red-Team-breach-and-ascend` | *(image à confirmer)* | `80` | HTTP (web → root) |

> Les **ports** ci-dessus correspondent à l'instruction `EXPOSE` du Dockerfile de chaque
> challenge (= le port interne à renseigner dans le plugin CTFd). Le port **exposé au joueur**
> est alloué dynamiquement par le plugin (32768+).

## 7. Rappels rapides

- Droits : le dépôt et Docker sur la VM nécessitent `sudo` (repo owner `ctfd`).
- Redémarrer CTFd si besoin : `sudo systemctl restart ctfd`.
- Voir les images : `sudo docker images` — les instances actives : `sudo docker ps`.
- Ne jamais committer : `challenge.env`, dumps, images (`.tar`), artefacts générés.

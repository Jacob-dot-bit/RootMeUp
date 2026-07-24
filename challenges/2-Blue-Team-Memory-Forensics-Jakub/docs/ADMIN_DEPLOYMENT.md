# Blue Team Memory Forensics — Guide Admin / Déploiement

Challenge de type **container** : une **boîte d'analyse accessible en SSH**. Le joueur
fait *Start Instance*, se connecte en SSH, et analyse le dump avec les outils déjà en
place (rien à installer côté joueur).

## 1) Fournir le flag (ne PAS le committer)

Le flag n'est pas codé en dur : il vient d'un fichier gitignoré, puis est cuit dans le
dump/PCAP au build, et son hash SHA256 est généré pour l'auto-vérification.

```bash
cd challenges/2-Blue-Team-Memory-Forensics-Jakub/setup
cp challenge.env.example challenge.env
$EDITOR challenge.env            # FLAG=blue{...}  (choisir une valeur rotée)
```
Si aucun `challenge.env` n'est fourni, le build réussit mais avec un flag **placeholder**.

> ⚠️ Rotation : l'ancien flag est resté public dans l'historique git — choisir une
> **nouvelle** valeur dans `challenge.env`.

## 2) Build de l'image

```bash
sudo docker build -t rootmeup/bt2-memory-forensics:1.0 \
  /srv/ctf-challenges/RootMeUp/challenges/2-Blue-Team-Memory-Forensics-Jakub
```

## 3) Test local

```bash
docker compose up --build -d          # expose 2222->22
ssh analyst@127.0.0.1 -p 2222         # mot de passe : forensics
# dans la boîte :
python3 vol_analyzer.py -f memory.dmp windows.pslist
```

Vérifier que le flag roté est bien cuit dans le dump :
```bash
sudo docker run --rm --entrypoint python3 rootmeup/bt2-memory-forensics:1.0 \
  vol_analyzer.py -f memory.dmp windows.strings --pid 6847 | grep -i FLAG=
```

## 4) Configuration CTFd

Identifiants SSH de la boîte : **`analyst` / `forensics`** (dans l'énoncé joueur).

**Challenge « point d'entrée » (type `container`)** — porte le bouton *Start Instance* :
- **Type** : `container`
- **Image** : `rootmeup/bt2-memory-forensics:1.0`
- **Port** : `22`
- **Connection Info** *(obligatoire, sinon pas de bouton)* :
  `Connectez-vous : ssh analyst@100.118.132.76 -p [port instance]  (mot de passe : forensics)`
- **Flag** : le PID → `6847` (Static, case sensitive)

**Série de flags** (catégorie `Blue Team — Memory Forensics`), les suivants en type `standard` :

| Flag | Question | Réponse |
|---|---|---|
| 1 (container) | PID du processus malveillant | `6847` |
| 2 (standard) | Nom de l'exécutable | `svchost_update.exe` |
| 3 (standard) | IP du serveur C2 | `185.141.27.83` |
| 4 (standard) | Domaine du C2 | `c2.darkops-syndicate.net` |
| 5 (standard) | Port du C2 | `4444` |
| 6 (standard) | Flag final | valeur de `challenge.env` (`blue{...}`) |

## 5) Séquence de validation

1. Laisser en `Hidden`.
2. *Start Instance* avec un compte de test → récupérer l'adresse/port.
3. `ssh analyst@<ip> -p <port>` (mdp `forensics`) → le shell doit s'ouvrir sur le home
   avec `memory.dmp` et les outils.
4. Lancer `python3 vol_analyzer.py -f memory.dmp windows.pslist` → doit fonctionner.
5. Soumettre les 6 réponses dans CTFd → toutes acceptées.
6. Passer en `Visible`.

## 6) Troubleshooting

```bash
sudo docker ps -a                       # l'instance tourne ? (mapping ...->22/tcp)
sudo docker logs <container_id>         # erreurs sshd ?
# « Could not get port » côté plugin → vérifier que l'image a bien EXPOSE 22 (c'est le cas).
```

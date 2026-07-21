# Blue Team Memory Forensics - Guide Admin/Deploiement

## 1) Build de l'image
Depuis `challenges/2-Blue-Team-Memory-Forensics`:

```bash
docker build -t blue-team-memory-forensics:latest .
```

## 2) Test local (mode dual : HTTP + terminal)

Lancer le conteneur localement pour vérifier que tout fonctionne :

```bash
docker run -it --rm -p 8000:8000 blue-team-memory-forensics:latest
```

- **HTTP (port 8000)** : artefacts disponibles à `http://localhost:8000/`
- **Terminal interactif** : outils d'analyse (`vol_analyzer.py`) utilisables directement

## 3) Export et transfert vers le serveur
```bash
docker save -o blue-team-memory-forensics.tar blue-team-memory-forensics:latest
scp -i "<SSH_KEY_PATH>" ".\blue-team-memory-forensics.tar" jakub@<IP_TAILSCALE_VM>:/tmp/
```

## 4) Import sur le serveur
```bash
docker load -i /tmp/blue-team-memory-forensics.tar
docker images | grep blue-team-memory-forensics
```

## 5) Configuration CTFd (soutenance)
Challenge type: `container`

- **Name**: `Blue Team - Jakub - Memoire et analyse de malware (Volatility)`
- **Category**: `Blue Team`
- **Image**: `blue-team-memory-forensics:latest`
- **Port**: `8000`
- **Command**: laisser vide (l'entrypoint gère tout : HTTP + terminal)
- **Initial Value**: `100`
- **Decay Limit**: `0`
- **Minimum Value**: `100`
- **Volumes**: vide

> **Note** : Le conteneur démarre automatiquement :
> 1. Un serveur HTTP sur le port 8000 → les joueurs téléchargent les artefacts via l'URL CTFd
> 2. Un terminal bash → accessible via `docker exec` pour les tests admin

## 6) Creation du flag (obligatoire)
Dans l'onglet `Flags`:
- **Type**: `Static`
- **Valeur**: `blue{m3m_f0r3ns1cs_v0l4t1l1ty_m4st3r}`
- **Case Sensitive**: activé

## 7) Sequence de validation
1. Laisser le challenge en `Hidden`.
2. Tester `Start Instance` avec un compte joueur.
3. Vérifier l'accès HTTP aux fichiers : `http://<instance>:8000/memory.dmp`
4. Vérifier que `hints.txt` et `network_capture.pcap` sont bien accessibles.
5. Soumettre le flag `blue{m3m_f0r3ns1cs_v0l4t1l1ty_m4st3r}` pour valider.
6. Passer en `Visible`.

## 8) Troubleshooting
Si l'instance ne démarre pas :

```bash
docker ps -a
docker logs <container_id>
```

Si l'image n'existe pas :

```bash
docker load -i /tmp/blue-team-memory-forensics.tar
```

Si le port 8000 ne répond pas :

```bash
# Vérifier que le serveur HTTP tourne dans le conteneur
docker exec <container_id> ps aux | grep http.server
```

## 9) Accès terminal admin (debug)
```bash
docker exec -it <container_id> bash
# Puis utiliser les outils d'analyse :
python3 tools/vol_analyzer.py -f challenge/memory.dmp windows.pslist
```

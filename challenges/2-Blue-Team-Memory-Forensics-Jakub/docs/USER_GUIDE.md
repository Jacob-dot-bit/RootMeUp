# Blue Team Memory Forensics - Guide Joueur

## Objectif
Analyser un dump mémoire Windows compromis pour identifier le processus malveillant, le serveur C2 et récupérer le flag final.

## Accès au challenge (via CTFd)

Ce challenge est un **environnement d'analyse fourni** : tout est déjà installé,
tu n'as **rien à mettre en place** sur ta machine.

1. Connecte-toi avec ton compte joueur et ouvre le challenge.
2. Clique sur **Start Instance** : CTFd t'affiche une **adresse** et un **port**.
3. Connecte-toi en **SSH** à la boîte d'analyse :
   ```bash
   ssh analyst@<IP> -p <PORT>
   # mot de passe : forensics
   ```
4. Tu arrives dans un shell où le dump et les outils sont **déjà en place**
   (le message d'accueil rappelle les commandes).

## Outils d'analyse (déjà dans la boîte)

> ⚠️ **Important** : le dump `memory.dmp` est dans un **format pédagogique dédié à ce
> challenge**, pas une image mémoire brute standard. Le vrai Volatility 3 (`vol.py`) ne
> sait pas le lire, et un `strings` classique ne révèle pas le flag (il est encodé).
> Utilise l'outil fourni : **`vol_analyzer.py`** (un « mini‑Volatility » qui reproduit
> les commandes `windows.*` sur ce format).

Dans ton home (`~`) :

```bash
# Syntaxe générale
python3 vol_analyzer.py -f memory.dmp <commande>

# Commandes disponibles :
#   windows.info      windows.pslist     windows.pstree    windows.netscan
#   windows.malfind   windows.dlllist    windows.handles   windows.dumpfiles
#   windows.strings   windows.registry
```

Fichiers et outils complémentaires :
- **`memory.dmp`** — le dump à analyser · **`network_capture.pcap`** — capture réseau (bonus) · **`hints.txt`** — indices.
- **`extract_strings.py`** — extraction/décodage des chaînes.
- **`check_flag.py`** — auto-vérification hors ligne de tes réponses (optionnel).

## Piste de résolution

Toutes les commandes ci-dessous se lancent via `python3 vol_analyzer.py -f memory.dmp <commande>`, **dans la boîte SSH**.

1. `windows.pslist` / `windows.pstree` — cherchez un nom ou une hiérarchie suspecte.
2. Identifiez le processus suspect en regardant son PPID et sa session.
3. `windows.netscan` — vérifiez les connexions réseau associées à ce PID.
4. `windows.malfind` — recherchez de l'injection mémoire.
5. `windows.strings --pid <PID>` (ou `tools/extract_strings.py`) — extrayez et analysez les chaînes du binaire malveillant.
6. Récupérez le flag caché dans la configuration du malware.

## Format du flag
`blue{...}`

## Soumission
Soumets tes réponses dans CTFd (série de flags : PID, exécutable, IP/domaine/port du C2, flag final).

## Indices
Si tu es bloqué, consulte `hints.txt` (dans ton home sur la boîte SSH).

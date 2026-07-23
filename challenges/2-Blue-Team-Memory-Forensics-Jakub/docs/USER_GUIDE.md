# Blue Team Memory Forensics - Guide Joueur

## Objectif
Analyser un dump mémoire Windows compromis pour identifier le processus malveillant, le serveur C2 et récupérer le flag final.

## Accès au challenge (via CTFd)

1. Connectez-vous avec votre compte joueur.
2. Ouvrez le challenge `Blue Team - Jakub - Memoire et analyse de malware (Volatility)`.
3. Cliquez sur `Start Instance` et notez l'URL d'instance fournie par CTFd.
4. Téléchargez les artefacts depuis l'URL d'instance :
   ```
   http://<instance>:8000/memory.dmp
   http://<instance>:8000/network_capture.pcap
   http://<instance>:8000/hints.txt
   ```

## Outils d'analyse

> ⚠️ **Important** : le dump `memory.dmp` est dans un **format pédagogique dédié à ce
> challenge**, pas une image mémoire brute standard. Le vrai Volatility 3 (`vol.py`) ne
> sait pas le lire, et un `strings` classique ne révèle pas le flag (il est encodé).
> Utilisez l'**outil fourni dans le conteneur** : `tools/vol_analyzer.py` (un
> « mini‑Volatility » qui reproduit les commandes `windows.*` sur ce format).

Depuis le terminal du challenge (ou après avoir récupéré les fichiers du dépôt) :

```bash
# Syntaxe générale
python3 tools/vol_analyzer.py -f challenge/memory.dmp <commande>

# Commandes disponibles :
#   windows.info      windows.pslist     windows.pstree    windows.netscan
#   windows.malfind   windows.dlllist    windows.handles   windows.dumpfiles
#   windows.strings   windows.registry
```

Outils complémentaires :
- **`tools/extract_strings.py`** — extraction/décodage des chaînes du binaire extrait.
- **Wireshark / `tshark`** — analyse du PCAP réseau (`network_capture.pcap`) pour l'étape bonus.

## Piste de résolution

Toutes les commandes ci-dessous se lancent via `python3 tools/vol_analyzer.py -f challenge/memory.dmp <commande>`.

1. `windows.pslist` / `windows.pstree` — cherchez un nom ou une hiérarchie suspecte.
2. Identifiez le processus suspect en regardant son PPID et sa session.
3. `windows.netscan` — vérifiez les connexions réseau associées à ce PID.
4. `windows.malfind` — recherchez de l'injection mémoire.
5. `windows.strings --pid <PID>` (ou `tools/extract_strings.py`) — extrayez et analysez les chaînes du binaire malveillant.
6. Récupérez le flag caché dans la configuration du malware.

## Format du flag
`blue{...}`

## Soumission
Soumettez le flag final dans CTFd depuis la page du challenge.

## Indices
Si vous êtes bloqué, consultez `hints.txt` téléchargé depuis l'instance.

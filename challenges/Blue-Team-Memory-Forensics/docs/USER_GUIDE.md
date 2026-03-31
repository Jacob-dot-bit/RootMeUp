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

## Outils recommandés (sur votre machine)
- **Volatility3** — analyse du dump mémoire (`vol.py`)
- **strings** — extraction de chaînes depuis un binaire
- **Wireshark** — analyse du PCAP réseau
- Ghidra / Radare2 (optionnel, pour l'analyse binaire avancée)

## Piste de résolution

1. Listez les processus (`pslist` / `pstree`) et cherchez un nom ou une hiérarchie suspecte.
2. Identifiez le processus suspect en regardant son PPID et sa session.
3. Vérifiez les connexions réseau (`netscan`) associées à ce PID.
4. Recherchez de l'injection mémoire (`malfind`).
5. Extrayez et analysez les strings du binaire malveillant.
6. Récupérez le flag caché dans la configuration du malware.

## Format du flag
`blue{...}`

## Soumission
Soumettez le flag final dans CTFd depuis la page du challenge.

## Indices
Si vous êtes bloqué, consultez `hints.txt` téléchargé depuis l'instance.

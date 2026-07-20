#!/bin/bash
# =============================================================================
#  Blue Team CTF – Script d'accueil du conteneur
#  Mode dual : HTTP (port 8000) pour le download des artefacts
#              + terminal interactif pour l'analyse locale
# =============================================================================

# ── Démarrer le serveur HTTP en arrière-plan ──────────────────────────────────
python3 -m http.server 8000 --directory /challenge/challenge &
HTTP_PID=$!
echo "[+] Serveur HTTP démarré sur le port 8000 (PID: $HTTP_PID)"

cat << 'BANNER'

 ╔══════════════════════════════════════════════════════════════╗
 ║                                                              ║
 ║   🔵  BLUE TEAM CTF – Mémoire et Analyse de Malware         ║
 ║                                                              ║
 ║   Jakub – ESGI Projet Annuel 2026                            ║
 ║                                                              ║
 ╠══════════════════════════════════════════════════════════════╣
 ║                                                              ║
 ║   📖 Contexte :                                             ║
 ║   L'attaquant a déployé un implant en mémoire qui            ║
 ║   communique avec un serveur C2.                             ║
 ║   Trouvez le C2 et le flag !                                 ║
 ║                                                              ║
 ║   🌐 Téléchargement des artefacts (via CTFd) :              ║
 ║     http://<instance>:8000/memory.dmp                        ║
 ║     http://<instance>:8000/network_capture.pcap              ║
 ║     http://<instance>:8000/hints.txt                         ║
 ║                                                              ║
 ║   📁 Fichiers disponibles localement :                      ║
 ║     challenge/memory.dmp       → Dump mémoire                ║
 ║     challenge/network_capture.pcap → Capture réseau (bonus)  ║
 ║     challenge/hints.txt        → Indices                     ║
 ║     report/report_template.md  → Rapport à remplir           ║
 ║                                                              ║
 ║   🔧 Outils d'analyse (dans ce terminal) :                  ║
 ║     python3 tools/vol_analyzer.py -f challenge/memory.dmp \  ║
 ║        windows.info | pslist | pstree | netscan |            ║
 ║        malfind | dlllist | handles | dumpfiles |             ║
 ║        strings | registry                                    ║
 ║                                                              ║
 ║   ✅ Validation :                                           ║
 ║     python3 solution/validate_flag.py                        ║
 ║                                                              ║
 ║   💡 Commencez par :                                        ║
 ║     python3 tools/vol_analyzer.py -f challenge/memory.dmp \  ║
 ║       windows.pslist                                         ║
 ║                                                              ║
 ╚══════════════════════════════════════════════════════════════╝

BANNER

# ── Mode dual : interactif (local) vs détaché (CTFd) ─────────────────────────
if [ -t 0 ]; then
    # TTY présent → mode interactif (docker run -it) : lancer bash
    exec "$@"
else
    # Pas de TTY → mode CTFd détaché : le conteneur vit via le serveur HTTP
    echo "[+] Mode non-interactif détecté (CTFd). En attente sur le serveur HTTP..."
    wait $HTTP_PID
fi

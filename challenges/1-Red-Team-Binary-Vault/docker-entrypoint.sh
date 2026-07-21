#!/bin/sh
# Sert le binaire vulnerable : une instance par connexion TCP.
set -e
PORT="${CHALLENGE_PORT:-9003}"
echo "[*] VAULT-9 en ecoute sur le port ${PORT}"
exec socat -T120 TCP-LISTEN:"${PORT}",reuseaddr,fork EXEC:"/challenge/vault",stderr

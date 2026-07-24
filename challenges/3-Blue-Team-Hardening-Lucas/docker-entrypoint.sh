#!/usr/bin/env bash
# -----------------------------------------------------------------------------
#  Point d'entree du conteneur Hardening.
#  Filet de securite : si l'environnement vulnerable n'a pas ete deploye,
#  on le (re)deploie avant de lancer le terminal web.
# -----------------------------------------------------------------------------
set -e

if [ ! -f /etc/cron.d/sysupdate ] && ! id support >/dev/null 2>&1; then
    echo "[entrypoint] (re)deploiement de l'environnement vulnerable..."
    bash /opt/setup/harden_setup.sh || true
fi

echo "[entrypoint] srv-legacy01 pret. Terminal web sur le port 8000."
echo "[entrypoint] Session joueur : utilisateur 'analyst' (sudo disponible)."

exec "$@"

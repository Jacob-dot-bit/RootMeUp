#!/bin/sh
# Boîte stand-alone VAULT-9.
# 1) Démarre le service vulnérable sous l'utilisateur 'vault' (seul à pouvoir lire
#    les flags), en écoute LOCALE : le joueur doit l'exploiter via `nc localhost 9003`,
#    il ne peut pas `cat` les flags depuis son compte.
# 2) Démarre sshd au premier plan (processus principal du conteneur).
set -e

su -s /bin/sh vault -c \
  'socat -T300 TCP-LISTEN:9003,bind=127.0.0.1,reuseaddr,fork EXEC:/challenge/vault,stderr' &

exec /usr/sbin/sshd -D -e

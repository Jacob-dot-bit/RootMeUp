#!/usr/bin/env bash
# =============================================================================
#  verify_hardening.sh — Test automatique de la validation (sans Docker).
#  Construit un arbre "vulnérable", vérifie que le grader côté serveur donne
#  0/10, applique les correctifs, vérifie 10/10. ADMIN ONLY.
# =============================================================================
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
BASE="$(dirname "$HERE")"
GRADER="$BASE/grader/grade.py"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

mk_vuln() {
  mkdir -p "$T/etc/ssh" "$T/etc/cron.d" "$T/usr/local/bin" "$T/opt/app" "$T/root/.ssh"
  printf 'PermitRootLogin yes\nPermitEmptyPasswords yes\n' > "$T/etc/ssh/sshd_config"
  printf 'root:x:0:0:root:/root:/bin/bash\nanalyst:x:1000:1000::/home/analyst:/bin/bash\nsupport:x:0:0:Support:/root:/bin/bash\n' > "$T/etc/passwd"
  : > "$T/etc/shadow"; chmod 644 "$T/etc/shadow"
  printf 'DB_PASSWORD=secret\n' > "$T/opt/app/.env"; chmod 644 "$T/opt/app/.env"
  echo 'callback' > "$T/etc/cron.d/sysupdate"
  printf 'telnet stream tcp nowait root /usr/sbin/in.telnetd\n' > "$T/etc/inetd.conf"
  echo '#!/bin/bash' > "$T/usr/local/bin/oldbackup"; chmod 4755 "$T/usr/local/bin/oldbackup"
  chmod 0777 "$T/usr/local/bin"
  echo 'ssh-rsa AAA ctf-attacker@evil' > "$T/root/.ssh/authorized_keys"
}
fix_all() {
  printf 'PermitRootLogin no\nPermitEmptyPasswords no\n' > "$T/etc/ssh/sshd_config"
  chmod 640 "$T/etc/shadow"; chmod 600 "$T/opt/app/.env"
  rm -f "$T/etc/cron.d/sysupdate"
  sed -i 's/^telnet/#telnet/' "$T/etc/inetd.conf"
  sed -i '/^support:/d' "$T/etc/passwd"
  chmod -s "$T/usr/local/bin/oldbackup"; chmod 0755 "$T/usr/local/bin"
  rm -f "$T/root/.ssh/authorized_keys"
}
score() { python3 "$GRADER" --target "$T" --score-only; }

echo "== Instance vulnerable =="; mk_vuln; before="$(score || true)"; echo "$before"
echo "== Apres durcissement =="; fix_all; after="$(score || true)"; echo "$after"

echo "-----------------------------------------"
if [ "$before" = "0/10" ] && [ "$after" = "10/10" ]; then
  echo "RESULTAT: OK (grader 0/10 -> 10/10)"; exit 0
else
  echo "RESULTAT: ECHEC"; exit 2
fi

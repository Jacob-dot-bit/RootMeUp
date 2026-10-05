#!/usr/bin/env bash
# Exporte la configuration de l'hyperviseur Proxmox dans infra/proxmox/host-config/.
#
# Seuls des fichiers sans secret sont copiés (liste blanche ci-dessous) :
# /etc/pve/priv, les clés TLS/SSH, shadow.cfg et tfa.cfg ne sont jamais récupérés.
#
# Usage : ./export.sh [cible-ssh]      (défaut : root@54.36.121.105)
set -euo pipefail

TARGET="${1:-root@54.36.121.105}"
DEST="$(cd "$(dirname "$0")" && pwd)/host-config"

FILES=(
  /etc/hostname
  /etc/hosts
  /etc/network/interfaces
  /etc/sysctl.d/99-ipforward.conf
  /etc/iptables/rules.v4
  /etc/iptables/rules.v6
  /etc/ssh/sshd_config.d/50-cloud-init.conf
  /etc/fail2ban/jail.d/rootmeup.local
  /etc/fail2ban/filter.d/proxmox.conf
  /etc/default/prometheus-node-exporter
  /etc/apt/sources.list.d/debian.sources
  /etc/apt/sources.list.d/proxmox.sources
  /etc/apt/sources.list.d/pve-enterprise.sources
  /etc/apt/sources.list.d/netbird.list
  /etc/apt/apt.conf.d/20auto-upgrades
  /etc/pve/storage.cfg
  /etc/pve/jobs.cfg
  /etc/pve/user.cfg
  /etc/pve/replication.cfg
)

rm -rf "$DEST"
mkdir -p "$DEST"

# Fichiers de la liste blanche (ceux absents sur l'hôte sont ignorés).
ssh "$TARGET" "tar -cf - --ignore-failed-read ${FILES[*]} 2>/dev/null" | tar -xf - -C "$DEST"

# Compteurs de paquets et horodatages retirés pour que le diff git ne montre que les vrais changements.
sed -i -e 's/\[[0-9]*:[0-9]*\]/[0:0]/' -e '/^# \(Generated\|Completed\)/d' "$DEST"/etc/iptables/rules.v*

# Configurations des VMs et conteneurs (sans les sections [snapshot], propres à l'hôte).
mkdir -p "$DEST/etc/pve/qemu-server" "$DEST/etc/pve/lxc"
for kind in qemu-server lxc; do
  for id in $(ssh "$TARGET" "ls /etc/pve/$kind/ 2>/dev/null | sed -n 's/\.conf$//p'"); do
    ssh "$TARGET" "sed -e '/^\[/,\$d' -e '/^parent:/d' /etc/pve/$kind/$id.conf" > "$DEST/etc/pve/$kind/$id.conf"
  done
done
rmdir --ignore-fail-on-non-empty "$DEST/etc/pve/lxc"

# Inventaire (lecture seule) : versions, paquets installés à la main, stockage ZFS, services.
mkdir -p "$DEST/inventory"
ssh "$TARGET" "pveversion -v"                                   > "$DEST/inventory/pveversion.txt"
ssh "$TARGET" "apt-mark showmanual"                             > "$DEST/inventory/packages-manual.txt"
ssh "$TARGET" "zpool list -H -o name,size,health; echo; zfs list -H -o name,mountpoint,compression" \
                                                                > "$DEST/inventory/zfs.txt"
ssh "$TARGET" "systemctl list-unit-files --state=enabled --no-legend --no-pager | awk '{print \$1}'" \
                                                                > "$DEST/inventory/services-enabled.txt"
ssh "$TARGET" "netbird status 2>/dev/null | grep -E '^(Management|FQDN|NetBird IP|Interface type|SSH Server):' || echo 'netbird non installé'" \
                                                                > "$DEST/inventory/netbird-status.txt"

# Garde-fou : refuse d'écrire un export contenant une clé privée ou un hash de mot de passe.
if grep -rlE 'PRIVATE KEY|^\$[0-9a-z]+\$|tskey-' "$DEST"; then
  echo "ERREUR : secret détecté dans l'export, rien ne doit être commité." >&2
  exit 1
fi

echo "Export terminé dans $DEST"

#!/usr/bin/env bash
# Sauvegarde les données applicatives des VMs pour pouvoir les restaurer avec Ansible :
#   - VM CTFd    : base MariaDB `ctfd` (comptes, équipes, scores, challenges, flags) + fichiers déposés
#   - VM Grafana : grafana.db (comptes, datasource MySQL, alertes créées dans l'UI)
#
# Ces fichiers contiennent des données sensibles : ils sont écrits HORS du dépôt
# (par défaut ~/rootmeup-backups/<date>) et ne doivent jamais être committés.
#
# Usage : ./backup-data.sh [dossier-de-sortie]
set -euo pipefail

CTF="${CTF_HOST:-jakub@ctf-rootmeup.tail8588a8.ts.net}"
GRAFANA="${GRAFANA_HOST:-root@grafana.tail8588a8.ts.net}"
OUT="${1:-$HOME/rootmeup-backups/$(date +%Y%m%d-%H%M%S)}"

mkdir -p "$OUT"
chmod 700 "$OUT"

echo "Base CTFd..."
ssh -t "$CTF" 'sudo -v' # demande le mot de passe sudo une fois
ssh "$CTF" 'sudo mysqldump --single-transaction --routines ctfd | gzip' > "$OUT/ctfd.sql.gz"

echo "Fichiers déposés CTFd..."
ssh "$CTF" 'sudo tar -C /opt/CTFd/CTFd -czf - uploads' > "$OUT/ctfd-uploads.tar.gz"

echo "Base Grafana (Grafana arrêté quelques secondes pour une copie cohérente)..."
ssh "$GRAFANA" 'systemctl stop grafana-server; cat /var/lib/grafana/grafana.db; systemctl start grafana-server' \
  > "$OUT/grafana.db"

chmod 600 "$OUT"/*
ls -lh "$OUT"
echo "Sauvegarde terminée dans $OUT"
echo "Restauration : ctfd_restore_from=$OUT et grafana_restore_from=$OUT (voir infra/proxmox/README.md)."

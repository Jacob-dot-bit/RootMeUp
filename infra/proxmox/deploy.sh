#!/usr/bin/env bash
# Redéploie la configuration de l'hyperviseur avec Ansible.
#
# Usage : ./deploy.sh [options ansible-playbook]   ex. ./deploy.sh --tags firewall --check --diff
set -euo pipefail
cd "$(dirname "$0")/ansible"

for f in inventory.ini secrets.yml; do
  if [[ ! -f $f ]]; then
    echo "Fichier manquant : ansible/$f (copier ${f%.*}.example.${f##*.} et le compléter)" >&2
    exit 1
  fi
done

command -v ansible-playbook >/dev/null || { echo "Installer Ansible : apt install ansible" >&2; exit 1; }
ansible-galaxy collection install -r requirements.yml >/dev/null

vault_opt=()
grep -q '^\$ANSIBLE_VAULT' secrets.yml && vault_opt=(--ask-vault-pass)

ansible-playbook site.yml -e @secrets.yml "${vault_opt[@]}" "$@"

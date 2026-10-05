# Hyperviseur Proxmox — configuration versionnée

Configuration de l'hôte OVH `ns3092722` (Proxmox VE 9, Debian 13) qui héberge les VMs
`100` (CTFd) et `101` (Grafana), et de quoi la redéployer.

| Élément | Rôle |
|---|---|
| [`host-config/`](host-config/) | Export brut de la configuration de l'hôte (fichiers `/etc` + inventaire). Référence, jamais appliqué tel quel. |
| [`export.sh`](export.sh) | Rafraîchit `host-config/` depuis l'hôte en production. |
| [`ansible/`](ansible/) | Playbook qui reconstruit l'hôte à partir d'une installation Proxmox neuve. |
| [`deploy.sh`](deploy.sh) | Lance le playbook après avoir vérifié l'inventaire et les secrets. |
| [`../vms/backup-data.sh`](../vms/backup-data.sh) | Sauvegarde les données des VMs (base CTFd, fichiers déposés, `grafana.db`) hors du dépôt. |

## Ce qui est configuré

| Domaine | Détail | Rôle Ansible |
|---|---|---|
| Dépôts, paquets | `pve-no-subscription`, dépôt entreprise désactivé, iptables-persistent, fail2ban, node_exporter, unattended-upgrades | `base` |
| Réseau | `vmbr0` sur `eno1` (IP publique `54.36.121.105`, IPv6 `2001:41d0:203:1c69::1`), `vmbr1` interne `192.168.100.1/24` sans port physique | `network` |
| Pare-feu | NAT de `192.168.100.0/24` vers Internet ; `22` et `8006` ouverts sur l'IP publique ; `3128` (SPICE) filtré sur l'IP publique | `firewall` |
| fail2ban | Jails `sshd` et `proxmox` (5 échecs / 10 min = 1 h de ban), tailnet et `vmbr1` en liste blanche | `fail2ban` |
| Tailscale | Nœud `ns3092722` du tailnet `tail8588a8`, Tailscale SSH activé | `tailscale` |
| Supervision | node_exporter écoute uniquement sur `192.168.100.1:9100` (scrapé par Prometheus) | `monitoring` |
| Stockage | Pool ZFS `data` (miroir NVMe) : `data/zd0` → `/var/lib/vz` (stockage `local`), `data/backups` → `/var/lib/vz/backups` (stockage `backups`, 2 sauvegardes gardées) | `storage` |
| Accès Proxmox | Groupe `Admins` (evan, lucas, sarah @pve) avec le rôle `Administrator` sur `/` | `pve_access` |
| Sauvegardes | vzdump des VMs 100 et 101 le dimanche à 01:00, mode stop, zstd | `backups` |
| VMs | Restauration de 100 et 101 depuis leurs archives vzdump | `guests` |

## Ce qui est installé dans les VMs

Deux options pour remettre les VMs : restaurer leurs archives vzdump (rôle `guests`, état
exact de la dernière sauvegarde), ou les réinstaller sur une Debian 13 neuve avec les rôles
ci-dessous puis réimporter les données.

| VM | Contenu | Rôle Ansible |
|---|---|---|
| `grafana` (101) | Grafana + Prometheus (loopback), HTTPS via `tailscale serve`, datasource et dashboards de [`infra/grafana/dashboards`](../grafana/dashboards/), 6 règles d'alerte, routage Discord CTFd / Proxmox, battement healthchecks.io, tunnel SSH vers la base CTFd, pare-feu, fail2ban (sshd, grafana, recidive), auditd | `grafana_vm` |
| `ctf-rootmeup` (100) | CTFd (venv + gunicorn) et plugin CTFdDockerContainersPlugin, MariaDB et Redis en loopback, nginx HTTPS (certificat `tailscale cert`), Docker, images des 7 challenges, cAdvisor, node_exporter, compte `tunnel`, sshd durci | `ctfd_vm` |

Les données ne sont pas dans le dépôt (comptes, scores, flags) : elles se sauvegardent avec
`backup-data.sh` puis se réimportent en renseignant `ctfd_restore_from` et
`grafana_restore_from` :

```bash
./infra/vms/backup-data.sh
```

```bash
./infra/proxmox/deploy.sh --limit grafana,ctfd -e ctfd_restore_from=$HOME/rootmeup-backups/<date> -e grafana_restore_from=$HOME/rootmeup-backups/<date>
```

## Secrets

Rien de secret n'est versionné. `export.sh` ne lit qu'une liste blanche de fichiers et
échoue s'il trouve une clé privée ou un hash de mot de passe. Ne sont **jamais** exportés :
`/etc/pve/priv/` (clés de cluster, `shadow.cfg`, `tfa.cfg`), les clés TLS de `pveproxy`,
les clés SSH de l'hôte.

Les valeurs nécessaires au redéploiement se mettent dans `ansible/secrets.yml` (ignoré par git),
créé depuis [`secrets.example.yml`](ansible/secrets.example.yml) puis chiffré :

```bash
cp ansible/secrets.example.yml ansible/secrets.yml
```

```bash
ansible-vault encrypt ansible/secrets.yml
```

## Mettre à jour l'export

Depuis une machine du tailnet (ou via l'IP publique) :

```bash
./infra/proxmox/export.sh root@ns3092722.tail8588a8.ts.net
```

Relire le diff de `host-config/` puis committer. Si une valeur a changé sur l'hôte, la
reporter dans `ansible/group_vars/all.yml` pour que le playbook reste fidèle.

## Redéployer l'hôte

1. **Installer Proxmox VE** depuis le manager OVH avec le gabarit Proxmox VE 9
   (RAID1 logiciel pour le système, pool ZFS `data` sur le reste des disques) et y déposer
   une clé SSH.
2. **Préparer le poste de contrôle** (Ansible ≥ 2.15) :

   ```bash
   sudo apt install ansible
   ```

   ```bash
   cp infra/proxmox/ansible/inventory.example.ini infra/proxmox/ansible/inventory.ini
   ```

   puis créer `secrets.yml` (voir ci-dessus) avec une clé d'authentification Tailscale neuve.
3. **Vérifier ce qui va changer**, puis appliquer :

   ```bash
   ./infra/proxmox/deploy.sh --check --diff
   ```

   ```bash
   ./infra/proxmox/deploy.sh
   ```

4. **Restaurer les VMs** : copier les archives vzdump dans `/var/lib/vz/backups/dump/` de
   l'hôte, renseigner leur nom dans `guests` (`group_vars/all.yml`), puis :

   ```bash
   ./infra/proxmox/deploy.sh --tags guests
   ```

5. **Après le déploiement** : changer les mots de passe initiaux des comptes Proxmox,
   activer la 2FA (TOTP) pour chacun, et vérifier que Prometheus scrape bien `192.168.100.1:9100`.

Chaque rôle a son tag (`--tags firewall`, `--tags fail2ban`…) pour n'appliquer qu'une partie.

## Points d'attention

- **SSH par clé uniquement** (`ssh_password_authentication: false`) : chaque administrateur
  doit avoir déposé sa clé publique dans `/etc/pve/priv/authorized_keys` (lien de
  `/root/.ssh/authorized_keys`) avant d'appliquer le rôle `base`.
- **Ports exposés hors administration** : `rpcbind` (`111`) et `postfix` (`25`) écoutent sur
  toutes les interfaces ; ils ne sont pas utilisés et peuvent être filtrés ou désactivés.
- **Rôle `ctfd_vm` partiellement reconstruit** : le service `ctfd`, le site nginx, la config
  Docker, MariaDB et sshd sont relevés sur la VM. La version de CTFd (`ctfd_version`), la
  config exacte du compte `tunnel`, le pare-feu, les jails fail2ban et les règles auditd de la
  VM CTFd n'ont pas pu être lus (droits root requis) et restent à compléter.
- La VM Grafana a aussi un bureau GNOME installé, qui n'est pas repris par le rôle.
- Appliquer le rôle `network` sur l'hôte en production recharge les interfaces : à faire
  avec la console KVM OVH à portée de main.

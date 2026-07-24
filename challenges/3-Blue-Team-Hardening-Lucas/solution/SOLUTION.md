# 🔓 SOLUTION — Operation IRON GATE (Hardening)  ⚠️ SPOILERS

Correctifs attendus, du plus simple au plus difficile. Réservé aux admins.
Toutes les commandes s'exécutent avec `sudo` dans le terminal web.

## 🟢 Palier FACILE (indice complet)

### Q1 — SSH root login → `NW{r00t_l0gin_disabled}`
```bash
sudo sed -i 's/^PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
```
### Q2 — Mots de passe vides → `NW{n0_empty_passw0rds}`
```bash
sudo sed -i 's/^PermitEmptyPasswords .*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
```
### Q3 — /etc/shadow → `NW{shadow_l0cked_down}`
```bash
sudo chmod 640 /etc/shadow
```

## 🟡 Palier MOYEN (indice partiel)

### Q4 — Secret applicatif → `NW{secrets_perms_600}`
Le fichier `/opt/app/.env` est lisible par tous.
```bash
sudo chmod 600 /opt/app/.env
```
### Q5 — Persistance planifiée → `NW{malicious_cron_purged}`
Une tâche cron rappelle un C2.
```bash
sudo rm /etc/cron.d/sysupdate
```
### Q6 — Service réseau → `NW{telnet_is_dead}`
Telnet (en clair) est actif dans `/etc/inetd.conf`.
```bash
sudo sed -i 's/^telnet/#telnet/' /etc/inetd.conf
```

## 🟠 Palier DIFFICILE (indice vague)

### Q7 — Accès admin caché → `NW{no_hidden_r00t_user}`
Un utilisateur possède l'UID 0 en plus de root (`awk -F: '$3==0' /etc/passwd`).
```bash
sudo sed -i '/^support:/d' /etc/passwd     # ou : sudo userdel support
```
### Q8 — Élévation de privilèges → `NW{suid_backdoor_cleared}`
Un binaire est SUID root (`find / -perm -4000 2>/dev/null`).
```bash
sudo chmod -s /usr/local/bin/oldbackup
```

## 🔴 Palier EXPERT (aucun indice)

### Q9 — Intégrité du PATH → `NW{writable_path_secured}`
`/usr/local/bin` (dans le PATH) est **world-writable** : n'importe qui peut y
déposer un binaire malveillant exécuté à la place d'un légitime.
Détection : `find / -type d -perm -0002 2>/dev/null | grep bin`.
```bash
sudo chmod 755 /usr/local/bin
```
### Q10 — Accès distant résiduel → `NW{ssh_backdoor_key_removed}`
Une clé publique d'attaquant traîne dans les `authorized_keys` de root.
Détection : `sudo cat /root/.ssh/authorized_keys`.
```bash
sudo rm /root/.ssh/authorized_keys
# ou retirer uniquement la ligne 'ctf-attacker'
```

---
## Vérification
```bash
# Dans le conteneur : progression du joueur (sans flag)
audit                              # -> 10/10 correctifs appliqués

# Côté serveur : validation + flags (source de vérité)
python3 grader/grade.py --target /chemin/rootfs      # ou --ssh root@<ip>
bash solution/verify_hardening.sh                    # test auto : 0/10 -> 10/10
```
Les flags sont détenus **uniquement** par `grader/grade.py` (côté serveur) et
récapitulés dans `../ctfd/flags.txt` (admin). Ils ne sont **pas** dans l'image.

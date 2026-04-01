Liste des exigences de sécurité appliquées :
- SSH par clé uniquement, connexion root interdite.
- Pare-feu iptables filtrant les flux entrants et sortants.
- Fail2Ban contre les tentatives de brute force.
- auditd pour la surveillance des actions sensibles (changements de mots de passe, modifications de fichiers).
- Politique de mots de passe stricte pour les comptes locaux.
- Mises à jour automatiques (unattended-upgrades).
- Durcissement conforme au benchmark CIS Debian.
- Cloisonnement des challenges via conteneurs Docker (un conteneur par équipe, géré par containerd).
- Accès à la plateforme restreint au réseau Tailscale.

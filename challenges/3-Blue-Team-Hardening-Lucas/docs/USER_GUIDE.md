# 🎮 Guide Joueur — Hardening : Operation IRON GATE

Vous êtes le nouvel administrateur Blue Team de **NORTHWIND**. Le serveur
**srv-legacy01** est truffé de mauvaises configurations. **Durcissez-le.**

## 1. Démarrer
1. Cliquez sur **Start Instance** dans CTFd.
2. Ouvrez le lien / port fourni → un **terminal web** s'ouvre.
3. Vous êtes connecté comme **`analyst`** (mot de passe `analyst`, `sudo` disponible).

## 2. La commande clé : `audit`
Tapez :
```bash
audit
```
Elle affiche votre **progression** sur les **10 contrôles de durcissement** :
- `[À CORRIGER]` → la faille est présente (avec un indice pour les niveaux faciles) ;
- `[OK]` → c'est corrigé.

> ℹ️ `audit` ne montre **pas** les flags : ils n'existent pas sur la machine
> (impossible à voler/reverser). Pour obtenir un flag, utilise `getflag`.

## 3. Récupérer un flag : `getflag <N>`
Une fois une faille corrigée (contrôle en `[OK]` dans `audit`), demande son flag :
```bash
getflag 1        # récupère le flag de la tâche 1
```
Le **serveur** re-vérifie lui-même que la faille est corrigée, puis te renvoie le
flag. Tu n'as plus qu'à le **coller dans CTFd**. Si la faille n'est pas encore
corrigée, `getflag` refuse (pas de triche possible).

## 4. Boucle de jeu
```
audit            # voir ma progression et ce qui reste à corriger
sudo ...         # j'applique le correctif
audit            # je vérifie que le contrôle passe en [OK]
getflag <N>      # le serveur valide et me donne le flag
<CTFd>           # je colle le flag -> niveau résolu
```

## 5. Les 10 contrôles (difficulté croissante)
Le challenge monte en difficulté : les premiers niveaux donnent un **indice
complet**, les derniers **aucun**. À vous d'enquêter.

| #  | Palier | Ce qu'il faut sécuriser |
|----|--------|-------------------------|
| 1  | 🟢 facile | Interdire la connexion **root** en SSH |
| 2  | 🟢 facile | Interdire les **mots de passe vides** |
| 3  | 🟢 facile | Protéger **/etc/shadow** |
| 4  | 🟡 moyen | Protéger un **secret applicatif** en clair |
| 5  | 🟡 moyen | Supprimer une **persistance planifiée** (cron) |
| 6  | 🟡 moyen | Désactiver un **service en clair** |
| 7  | 🟠 difficile | Supprimer un **accès administrateur illégitime** |
| 8  | 🟠 difficile | Neutraliser une **élévation de privilèges** |
| 9  | 🔴 expert | **Aucun indice** — problème d'intégrité du PATH |
| 10 | 🔴 expert | **Aucun indice** — accès distant résiduel sur root |

Commandes d'investigation utiles pour les niveaux durs :
`find / -perm -4000 2>/dev/null` (SUID), `awk -F: '$3==0' /etc/passwd`
(comptes UID 0), `find / -type d -perm -0002 2>/dev/null` (dossiers
world-writable), `sudo cat /root/.ssh/authorized_keys` (clés SSH).

## 6. Rappels de commandes utiles
```bash
sudo vim /etc/ssh/sshd_config        # éditer un fichier
sudo chmod 640 /etc/shadow           # changer des permissions
sudo chmod -s /chemin/binaire        # retirer un bit SUID
sudo rm /etc/cron.d/xxx              # supprimer un fichier
sudo userdel <user>                  # (ou éditer /etc/passwd) supprimer un compte
sudo grep -R NOPASSWD /etc/sudoers.d # inspecter les règles sudo
stat -c '%a %n' <fichier>            # voir les permissions en octal
```

## 7. Astuces
- Lisez bien l'**indice** de chaque ligne `[A CORRIGER]`.
- Les flags sont au format `NW{...}`, **sensibles à la casse**.
- Vous ne pouvez rien casser d'irréversible : l'instance est jetable, relancez-la si besoin.
- Ne supprimez pas le `sudo` de l'utilisateur **`analyst`** (c'est votre accès admin).

Bon durcissement ! 🛡️

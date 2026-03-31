# 🔵 Solution Complète – Blue Team Memory Forensics

> ⚠️ **SPOILERS** – Ne lisez ceci qu'après avoir tenté le challenge !

---

## 📋 Réponses Attendues

| Élément                | Réponse                                    |
|------------------------|--------------------------------------------|
| **PID malveillant**    | `6847`                                     |
| **Nom de l'exécutable**| `svchost_update.exe`                       |
| **IP du C2**           | `185.141.27.83`                            |
| **Domaine C2**         | `c2.darkops-syndicate.net`                 |
| **Port C2**            | `4444`                                     |
| **Flag**               | `blue{m3m_f0r3ns1cs_v0l4t1l1ty_m4st3r}`    |

---

## 🔎 Walkthrough Étape par Étape

### Étape 1 : Reconnaissance du dump

```bash
python tools/vol_analyzer.py -f challenge/memory.dmp windows.info
```

**Ce qu'on apprend :**
- Machine Windows 10 x64 (build 19045)
- Hostname : `DESKTOP-F4K3LAB`
- Utilisateur : `admin`
- Capture le 2026-02-20 à 15:00:00

---

### Étape 2 : Lister les processus (`pslist`)

```bash
python tools/vol_analyzer.py -f challenge/memory.dmp windows.pslist
```

**Ce qu'on observe :**
- Tous les processus système standards sont présents (System, smss.exe, csrss.exe, services.exe, etc.)
- Un processus **`svchost_update.exe`** (PID **6847**) est surligné en jaune → il ne fait pas partie des processus Windows légitimes
- Son PPID est **1052** (un `svchost.exe` légitime), mais il est en **Session 1** ce qui est inhabituel pour un enfant de svchost
- Il a été créé à `14:23:47`, peu après le lancement de `cmd.exe` (14:22:18)

**Indices clés :**
1. Le nom `svchost_update.exe` imite `svchost.exe` mais n'existe pas dans Windows
2. Le chemin est `C:\Users\admin\AppData\Local\Temp\` — pas `C:\Windows\System32\`
3. Créé juste après un `cmd.exe` → probable exécution manuelle

---

### Étape 3 : Voir l'arbre des processus (`pstree`)

```bash
python tools/vol_analyzer.py -f challenge/memory.dmp windows.pstree
```

**Ce qu'on confirme :**
- `svchost_update.exe` apparaît comme enfant de `svchost.exe` (PID 1052) mais il est affiché en **rouge** car son parentage est illogique
- Un vrai `svchost.exe` est toujours enfant direct de `services.exe` (PID 756)

---

### Étape 4 : Scanner les connexions réseau (`netscan`)

```bash
python tools/vol_analyzer.py -f challenge/memory.dmp windows.netscan
```

**Ce qu'on trouve :**
- Le PID **6847** a **deux connexions ESTABLISHED** :
  - `192.168.1.47:49847` → `185.141.27.83:4444` (C2 principal)
  - `192.168.1.47:49902` → `185.141.27.83:8443` (C2 backup/exfiltration)
- Ces connexions sont surlignées en **rouge** (IP 185.141.x.x)
- L'IP `185.141.27.83` est le serveur C2

---

### Étape 5 : Détecter les injections mémoire (`malfind`)

```bash
python tools/vol_analyzer.py -f challenge/memory.dmp windows.malfind
```

**Résultats :**
1. **PID 6847 (`svchost_update.exe`)** – Adresse `0x00400000`
   - Protection : `PAGE_EXECUTE_READWRITE` (RWX)
   - Header `MZ` → exécutable PE en mémoire
   - Mémoire privée non mappée à un module légitime

2. **PID 3200 (`explorer.exe`)** – Adresse `0x02A10000`
   - Protection : `PAGE_EXECUTE_READWRITE` (RWX)
   - Shellcode classique (`cld; call; pushad; mov ebp,esp; xor eax,eax...`)
   - Injection dans un processus légitime (technique de pivoting)

---

### Étape 6 : Examiner les DLLs chargées

```bash
python tools/vol_analyzer.py -f challenge/memory.dmp windows.dlllist --pid 6847
```

**DLLs suspectes chargées par le malware :**
- `ws2_32.dll` (Winsock) → communication réseau
- `wininet.dll` → API HTTP
- `winhttp.dll` → API HTTP de haut niveau

→ Confirme un implant qui communique en HTTP sur le réseau.

---

### Étape 7 : Examiner les handles

```bash
python tools/vol_analyzer.py -f challenge/memory.dmp windows.handles --pid 6847
```

**Handles révélateurs :**
- `\REGISTRY\...\CurrentVersion\Run` → **persistance via le registre**
- `\...\BaseNamedObjects\Global\MSUpdateCheck_47` → **mutex** (empêche l'exécution multiple)
- `\Device\NamedPipe\msupdate_47` → **named pipe** (communication inter-processus)

---

### Étape 8 : Vérifier la persistance registre

```bash
python tools/vol_analyzer.py -f challenge/memory.dmp windows.registry
```

**Entrée suspecte :**
```
Key:  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Name: WindowsSecurityUpdate
Data: C:\Users\admin\AppData\Local\Temp\svchost_update.exe
```
→ Le malware s'est ajouté au démarrage automatique !

---

### Étape 9 : Extraire le binaire (`dumpfiles`)

```bash
python tools/vol_analyzer.py -f challenge/memory.dmp windows.dumpfiles --pid 6847 --output extracted
```

**Résultat :** Fichier `extracted/pid.6847.svchost_update.exe` créé

---

### Étape 10 : Analyser les strings

```bash
python tools/vol_analyzer.py -f challenge/memory.dmp windows.strings --pid 6847
```

Ou avec l'outil dédié :

```bash
python tools/extract_strings.py extracted/pid.6847.svchost_update.exe
```

**Chaînes CRITIQUES trouvées :**
```
C2_PRIMARY=c2.darkops-syndicate.net:4444
C2_FALLBACK=185.141.27.83:8443
BEACON_SLEEP=30
XOR_KEY=X0rK3y!@#2026
EXFIL_TAG=CONFIDENTIAL_PROJECT_OMEGA_FILES
FLAG=blue{m3m_f0r3ns1cs_v0l4t1l1ty_m4st3r}
```

**Chaînes SUSPECTES :**
```
cmd.exe /c whoami
cmd.exe /c ipconfig /all
cmd.exe /c net user
cmd.exe /c systeminfo
POST /api/beacon HTTP/1.1
Host: c2.darkops-syndicate.net
powershell -ep bypass -nop -w hidden -c "IEX(...)"
```

→ **FLAG TROUVÉ : `blue{m3m_f0r3ns1cs_v0l4t1l1ty_m4st3r}`**

---

### Étape 11 (Bonus) : Analyse du PCAP

Ouvrir `challenge/network_capture.pcap` dans Wireshark :

```
tshark -r challenge/network_capture.pcap -Y "tcp.port == 4444"
```

**Observations :**
1. Résolution DNS de `c2.darkops-syndicate.net` → `185.141.27.83`
2. Beacons HTTP POST réguliers toutes les 30 secondes vers `/api/beacon`
3. Réponses du C2 contenant des commandes encodées en Base64
4. Trafic d'exfiltration sur le port 8443 (`/upload/0`, `/upload/1`, `/upload/2`)
5. Le flag apparaît dans une réponse C2 encodée en Base64

---

## 🧩 Résumé de l'attaque

```
Timeline de l'attaque :
──────────────────────────────────────────────────────────
08:00  → Boot Windows normal
09:15  → L'utilisateur ouvre Chrome
10:30  → L'utilisateur ouvre Notepad
14:22  → ⚠️  cmd.exe lancé (vecteur d'infection initial)
14:23  → 🔴 svchost_update.exe exécuté depuis %TEMP%
         → Connexion C2 établie (185.141.27.83:4444)
         → Injection de code dans explorer.exe
         → Clé de registre Run ajoutée (persistance)
         → Beacon toutes les 30s
         → Exfiltration via port 8443
15:00  → Capture mémoire effectuée
──────────────────────────────────────────────────────────
```

---

## 🛡️ Indicateurs de Compromission (IoC)

| Type         | Valeur                                          |
|--------------|-------------------------------------------------|
| IP           | `185.141.27.83`                                 |
| Domaine      | `c2.darkops-syndicate.net`                      |
| Port         | `4444` (beacon), `8443` (exfiltration)          |
| Processus    | `svchost_update.exe`                            |
| Chemin       | `C:\Users\admin\AppData\Local\Temp\`            |
| Mutex        | `Global\MSUpdateCheck_47`                       |
| Named Pipe   | `\\.\pipe\msupdate_47`                          |
| Registre     | `HKLM\...\Run\WindowsSecurityUpdate`            |
| User-Agent   | `Mozilla/5.0 (Windows NT 10.0; Win64; x64)...`  |
| URI Pattern  | `/api/beacon`, `/upload/*`                      |

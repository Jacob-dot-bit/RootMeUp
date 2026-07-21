#!/usr/bin/env python3
"""
=============================================================================
  Blue Team CTF – vol_analyzer.py
  Mini-Volatility : outil d'analyse de dump mémoire pour le challenge
=============================================================================
Commandes supportées (inspirées de Volatility 3) :
  windows.info        - Informations système
  windows.pslist      - Liste des processus
  windows.pstree      - Arbre des processus
  windows.netscan     - Connexions réseau
  windows.malfind     - Détection d'injections mémoire
  windows.dlllist     - DLLs chargées (pour un PID)
  windows.handles     - Handles ouverts (pour un PID)
  windows.dumpfiles   - Extraire les fichiers d'un processus
  windows.strings     - Extraire les chaînes d'un processus
  windows.registry    - Artefacts registre (persistence)

Usage :
  python vol_analyzer.py -f <dump> <commande> [--pid <PID>] [--output <dir>]
"""

import argparse
import struct
import json
import base64
import os
import sys
import hashlib
import re
from datetime import datetime

# ─── Constantes (doivent correspondre au générateur) ──────────────────────────

MAGIC = b"MEMDUMP1"
SECTION_PROCESS_TABLE  = 0x01
SECTION_NETWORK_TABLE  = 0x02
SECTION_MALFIND        = 0x03
SECTION_MALWARE_BINARY = 0x04
SECTION_DLL_LIST       = 0x05
SECTION_HANDLES        = 0x06
SECTION_REGISTRY       = 0x07
SECTION_METADATA       = 0xFF

# ─── Couleurs terminal ────────────────────────────────────────────────────────

class Colors:
    HEADER  = "\033[95m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    RED     = "\033[91m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

def colored(text, color):
    return f"{color}{text}{Colors.RESET}"


# ═══════════════════════════════════════════════════════════════════════════════
#   Lecteur de dump
# ═══════════════════════════════════════════════════════════════════════════════

class MemoryDumpReader:
    def __init__(self, filepath):
        self.filepath = filepath
        self.sections = {}
        self._parse()

    def _parse(self):
        with open(self.filepath, "rb") as fp:
            magic = fp.read(8)
            if magic != MAGIC:
                print(colored("[!] ERREUR : Ce fichier n'est pas un dump mémoire valide.", Colors.RED))
                sys.exit(1)

            version = struct.unpack("<H", fp.read(2))[0]
            fp.read(64)  # skip padding

            while True:
                header = fp.read(5)
                if len(header) < 5:
                    break
                section_type, size = struct.unpack("<BI", header)
                raw = fp.read(size)
                if len(raw) < size:
                    break
                try:
                    data = json.loads(raw.decode("utf-8"))
                    self.sections[section_type] = data
                except:
                    pass  # bruit final

    def get_processes(self):
        return self.sections.get(SECTION_PROCESS_TABLE, [])

    def get_network(self):
        return self.sections.get(SECTION_NETWORK_TABLE, [])

    def get_malfind(self):
        return self.sections.get(SECTION_MALFIND, [])

    def get_malware_binary(self):
        return self.sections.get(SECTION_MALWARE_BINARY, {})

    def get_dlls(self):
        return self.sections.get(SECTION_DLL_LIST, [])

    def get_handles(self):
        return self.sections.get(SECTION_HANDLES, [])

    def get_registry(self):
        return self.sections.get(SECTION_REGISTRY, [])

    def get_metadata(self):
        return self.sections.get(SECTION_METADATA, {})


# ═══════════════════════════════════════════════════════════════════════════════
#   Commandes d'analyse
# ═══════════════════════════════════════════════════════════════════════════════

def banner():
    print(colored(r"""
 ╔══════════════════════════════════════════════════════════╗
 ║       __  ___                ___              __         ║
 ║      /  |/  /__ __ _  ___  / _ |___  ___ _  / /__ ____   ║
 ║     / /|_/ / -_)  ' \/ _ \/ __ / _ \/ _ `/ / / -_) __/   ║
 ║    /_/  /_/\__/_/_/_/\___/_/ |_\___/\_,_/ /_/\__/_/      ║
 ║                                                          ║
 ║    Blue Team CTF - Memory Forensics Analyzer v1.0        ║
 ║    Compatible : challenge memory.dmp format              ║
 ╚══════════════════════════════════════════════════════════╝
    """, Colors.BLUE))


def cmd_info(reader, args):
    """windows.info – Informations système."""
    meta = reader.get_metadata()
    if not meta:
        print(colored("[!] Métadonnées non trouvées.", Colors.RED))
        return

    print(colored("\n[*] Volatility 3 Framework - windows.info.Info\n", Colors.CYAN))
    print(f"  {'Variable':<30} {'Value'}")
    print(f"  {'─' * 30} {'─' * 40}")
    mapping = {
        "Kernel Base":       "image_type",
        "KDBG Offset":       "kdbg_offset",
        "DTB":               "dtb",
        "Hostname":          "hostname",
        "Username":          "username",
        "Capture Time":      "capture_time",
        "Capture Tool":      "capture_tool",
        "Memory Size (raw)": "memory_size",
    }
    for label, key in mapping.items():
        val = meta.get(key, "N/A")
        if key == "memory_size":
            val = f"{int(val):,} bytes ({int(val)//1024//1024} MB)"
        print(f"  {label:<30} {val}")
    print()


def cmd_pslist(reader, args):
    """windows.pslist – Liste des processus."""
    processes = reader.get_processes()
    if not processes:
        print(colored("[!] Aucun processus trouvé.", Colors.RED))
        return

    print(colored("\n[*] Volatility 3 Framework - windows.pslist.PsList\n", Colors.CYAN))
    header = f"  {'PID':<8} {'PPID':<8} {'ImageFileName':<26} {'CreateTime':<22} {'Threads':<9} {'Handles':<9} {'SessionId'}"
    print(colored(header, Colors.BOLD))
    print(f"  {'─'*8} {'─'*8} {'─'*26} {'─'*22} {'─'*9} {'─'*9} {'─'*9}")

    for p in sorted(processes, key=lambda x: x["pid"]):
        line = f"  {p['pid']:<8} {p['ppid']:<8} {p['name']:<26} {p.get('create_time',''):<22} {p.get('threads',0):<9} {p.get('handles',0):<9} {p.get('session',0)}"

        # Surligner les processus suspects
        is_suspect = False
        if p["name"] not in [
            "System", "Registry", "smss.exe", "csrss.exe", "wininit.exe",
            "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe",
            "spoolsv.exe", "VBoxService.exe", "SecurityHealth.exe",
            "taskhostw.exe", "sihost.exe", "dwm.exe", "explorer.exe",
            "SecurityHealthTray.exe", "OneDrive.exe", "MsMpEng.exe",
            "chrome.exe", "notepad.exe", "cmd.exe"
        ]:
            is_suspect = True

        if is_suspect:
            print(colored(line, Colors.YELLOW))
        else:
            print(line)

    print(f"\n  Total : {len(processes)} processus")
    if any(p["name"] not in [
        "System", "Registry", "smss.exe", "csrss.exe", "wininit.exe",
        "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe",
        "spoolsv.exe", "VBoxService.exe", "SecurityHealth.exe",
        "taskhostw.exe", "sihost.exe", "dwm.exe", "explorer.exe",
        "SecurityHealthTray.exe", "OneDrive.exe", "MsMpEng.exe",
        "chrome.exe", "notepad.exe", "cmd.exe"
    ] for p in processes):
        print(colored("  [!] Des processus avec des noms inhabituels ont été détectés (surlignés).", Colors.YELLOW))
    print()


def cmd_pstree(reader, args):
    """windows.pstree – Arbre des processus."""
    processes = reader.get_processes()

    print(colored("\n[*] Volatility 3 Framework - windows.pstree.PsTree\n", Colors.CYAN))
    header = f"  {'PID':<8} {'PPID':<8} {'ImageFileName':<26} {'Threads':<9} {'Handles':<9} {'CreateTime'}"
    print(colored(header, Colors.BOLD))
    print(f"  {'─'*8} {'─'*8} {'─'*26} {'─'*9} {'─'*9} {'─'*22}")

    # Construire l'arbre
    by_ppid = {}
    for p in processes:
        by_ppid.setdefault(p["ppid"], []).append(p)

    def print_tree(pid, depth=0):
        children = by_ppid.get(pid, [])
        for p in sorted(children, key=lambda x: x["pid"]):
            prefix = "  " + "│ " * max(0, depth-1) + ("├─" if depth > 0 else "") + " "
            name_display = p["name"]
            line = f"{prefix}{p['pid']:<8} {p['ppid']:<8} {name_display:<26} {p.get('threads',0):<9} {p.get('handles',0):<9} {p.get('create_time','')}"

            # Surligner parentage illogique
            is_suspicious = False
            if "svchost" in p["name"].lower() and p["name"] != "svchost.exe":
                is_suspicious = True
            if p["name"] not in [
                "System", "Registry", "smss.exe", "csrss.exe", "wininit.exe",
                "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe",
                "spoolsv.exe", "VBoxService.exe", "SecurityHealth.exe",
                "taskhostw.exe", "sihost.exe", "dwm.exe", "explorer.exe",
                "SecurityHealthTray.exe", "OneDrive.exe", "MsMpEng.exe",
                "chrome.exe", "notepad.exe", "cmd.exe"
            ]:
                is_suspicious = True

            if is_suspicious:
                print(colored(line, Colors.RED))
            else:
                print(line)
            print_tree(p["pid"], depth + 1)

    print_tree(0)
    print()


def cmd_netscan(reader, args):
    """windows.netscan – Connexions réseau."""
    connections = reader.get_network()

    print(colored("\n[*] Volatility 3 Framework - windows.netscan.NetScan\n", Colors.CYAN))
    header = f"  {'Proto':<10} {'LocalAddr':<28} {'ForeignAddr':<32} {'State':<16} {'PID':<8} {'Process'}"
    print(colored(header, Colors.BOLD))
    print(f"  {'─'*10} {'─'*28} {'─'*32} {'─'*16} {'─'*8} {'─'*20}")

    processes = {p["pid"]: p["name"] for p in reader.get_processes()}

    for c in connections:
        pid = c["pid"]
        pname = processes.get(pid, "Unknown")
        state = c.get("state", "")
        line = f"  {c['proto']:<10} {c['local']:<28} {c['remote']:<32} {state:<16} {pid:<8} {pname}"

        # Surligner les connexions vers des IP externes suspectes
        if "185.141." in c.get("remote", ""):
            print(colored(line, Colors.RED))
        else:
            print(line)

    print(f"\n  Total : {len(connections)} connexions")
    print()


def cmd_malfind(reader, args):
    """windows.malfind – Détection d'injections."""
    sections = reader.get_malfind()
    pid_filter = args.pid

    print(colored("\n[*] Volatility 3 Framework - windows.malfind.Malfind\n", Colors.CYAN))

    for s in sections:
        if pid_filter and s["pid"] != pid_filter:
            continue

        print(colored(f"  Process: {s['process']}  PID: {s['pid']}  Address: {s['address']}", Colors.RED))
        print(colored(f"  Protection: {s['protection']}  Tag: {s['tag']}", Colors.YELLOW))
        print(colored(f"  Info: {s['description']}", Colors.DIM))
        print()
        print(f"  Hex Dump:")
        for hex_line in s["hex_dump"].split("\n"):
            print(f"    {hex_line}")
        print()
        print(f"  Disassembly:")
        for asm_line in s["disasm"].split("\n"):
            if asm_line.strip():
                print(f"    {asm_line}")
        print()
        print("  " + "─" * 60)
        print()

    if not sections:
        print("  Aucune injection détectée.")
    print()


def cmd_dlllist(reader, args):
    """windows.dlllist – DLLs chargées."""
    dlls = reader.get_dlls()
    pid_filter = args.pid

    print(colored("\n[*] Volatility 3 Framework - windows.dlllist.DllList\n", Colors.CYAN))

    if pid_filter:
        dlls = [d for d in dlls if d["pid"] == pid_filter]
        if not dlls:
            print(f"  Aucune DLL trouvée pour le PID {pid_filter}.")
            print(f"  (Seules les DLLs du processus malveillant sont indexées dans ce challenge)")
            print()
            return

    header = f"  {'PID':<8} {'Base':<14} {'Size':<12} {'Name':<25} {'Path'}"
    print(colored(header, Colors.BOLD))
    print(f"  {'─'*8} {'─'*14} {'─'*12} {'─'*25} {'─'*50}")

    for d in dlls:
        line = f"  {d['pid']:<8} {d['base']:<14} {d['size']:<12} {d['name']:<25} {d['path']}"
        if "ws2_32" in d["name"] or "wininet" in d["name"] or "winhttp" in d["name"]:
            print(colored(line, Colors.YELLOW))
        elif "svchost_update" in d["name"]:
            print(colored(line, Colors.RED))
        else:
            print(line)

    print()


def cmd_handles(reader, args):
    """windows.handles – Handles ouverts."""
    handles = reader.get_handles()
    pid_filter = args.pid

    print(colored("\n[*] Volatility 3 Framework - windows.handles.Handles\n", Colors.CYAN))

    if pid_filter:
        handles = [h for h in handles if h["pid"] == pid_filter]

    if not handles:
        print(f"  Aucun handle trouvé{' pour le PID ' + str(pid_filter) if pid_filter else ''}.")
        print()
        return

    header = f"  {'PID':<8} {'Handle':<10} {'Type':<12} {'Name'}"
    print(colored(header, Colors.BOLD))
    print(f"  {'─'*8} {'─'*10} {'─'*12} {'─'*60}")

    for h in handles:
        line = f"  {h['pid']:<8} {h['handle']:<10} {h['type']:<12} {h['name']}"
        if "Run" in h["name"] or "NamedPipe" in h["name"] or "Mutant" in h["name"]:
            print(colored(line, Colors.YELLOW))
        else:
            print(line)

    print()


def cmd_registry(reader, args):
    """windows.registry – Artefacts registre."""
    entries = reader.get_registry()

    print(colored("\n[*] Volatility 3 Framework - windows.registry.PrintKey\n", Colors.CYAN))

    for entry in entries:
        print(colored(f"  Key:   {entry['key']}", Colors.BOLD))
        print(f"  Name:  {entry['value_name']}")
        print(f"  Type:  {entry['value_type']}")
        value = entry['value_data']
        if "svchost_update" in str(value):
            print(colored(f"  Data:  {value}", Colors.RED))
        else:
            print(f"  Data:  {value}")
        print(f"  {'─' * 60}")
        print()


def cmd_dumpfiles(reader, args):
    """windows.dumpfiles – Extraire les fichiers d'un processus."""
    pid_filter = args.pid
    output_dir = args.output or "dump_output"

    if not pid_filter:
        print(colored("[!] Veuillez spécifier un PID avec --pid <PID>", Colors.RED))
        return

    malware = reader.get_malware_binary()
    if not malware or malware.get("pid") != pid_filter:
        print(colored(f"[!] Aucun fichier extractible trouvé pour le PID {pid_filter}.", Colors.YELLOW))
        print(f"    (Essayez avec le PID du processus suspect)")
        return

    os.makedirs(output_dir, exist_ok=True)

    # Extraire le binaire en format base64 (évite les blocages antivirus)
    binary_data = base64.b64decode(malware["binary_b64"])
    safe_name = malware['name'].replace('.exe', '').replace('.dll', '')
    bin_name = f"pid_{pid_filter}_{safe_name}.b64"
    bin_path = os.path.join(output_dir, bin_name)

    with open(bin_path, "w", encoding="utf-8") as f:
        f.write(malware["binary_b64"])

    print(colored(f"\n[*] Volatility 3 Framework - windows.dumpfiles.DumpFiles\n", Colors.CYAN))
    print(f"  PID:      {pid_filter}")
    print(f"  Process:  {malware['name']}")
    print(f"  Output:   {bin_path}")
    print(f"  Size:     {len(binary_data):,} bytes")
    print(f"  MD5:      {malware['md5']}")
    print(f"  SHA256:   {malware['sha256']}")
    print()
    print(colored(f"  [✓] Fichier extrait avec succès : {bin_path}", Colors.GREEN))
    print(f"  [i] Analysez avec : python tools/extract_strings.py {bin_path}")
    print()


def cmd_strings(reader, args):
    """windows.strings – Extraire les chaînes (du binaire malveillant)."""
    pid_filter = args.pid
    min_length = 4

    malware = reader.get_malware_binary()
    if pid_filter and malware and malware.get("pid") != pid_filter:
        print(colored(f"[!] Pas de données strings pour le PID {pid_filter}.", Colors.YELLOW))
        return

    if not malware:
        print(colored("[!] Aucun binaire malveillant trouvé dans le dump.", Colors.RED))
        return

    binary_data = base64.b64decode(malware["binary_b64"])

    print(colored(f"\n[*] Strings extraction – PID {malware['pid']} ({malware['name']})\n", Colors.CYAN))

    # Extraire les strings ASCII
    strings_found = []
    current = ""
    for byte in binary_data:
        if 32 <= byte < 127:
            current += chr(byte)
        else:
            if len(current) >= min_length:
                strings_found.append(current)
            current = ""
    if len(current) >= min_length:
        strings_found.append(current)

    for i, s in enumerate(strings_found):
        # Coloriser les strings intéressantes
        if any(kw in s.lower() for kw in ["c2", "flag", "beacon", "cmd.exe", "http", "host:", "pipe", "xor", "exfil"]):
            print(colored(f"  {i+1:>4}: {s}", Colors.RED))
        elif any(kw in s.lower() for kw in [".dll", "virtual", "create", "write", "internet", "alloc", "thread"]):
            print(colored(f"  {i+1:>4}: {s}", Colors.YELLOW))
        else:
            print(f"  {i+1:>4}: {s}")

    print(f"\n  Total : {len(strings_found)} chaînes trouvées")
    print()


# ═══════════════════════════════════════════════════════════════════════════════
#   CLI
# ═══════════════════════════════════════════════════════════════════════════════

COMMANDS = {
    "windows.info":      cmd_info,
    "windows.pslist":    cmd_pslist,
    "windows.pstree":    cmd_pstree,
    "windows.netscan":   cmd_netscan,
    "windows.malfind":   cmd_malfind,
    "windows.dlllist":   cmd_dlllist,
    "windows.handles":   cmd_handles,
    "windows.dumpfiles": cmd_dumpfiles,
    "windows.strings":   cmd_strings,
    "windows.registry":  cmd_registry,
}


def main():
    parser = argparse.ArgumentParser(
        description="Blue Team CTF - Memory Forensics Analyzer (mini-Volatility)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commandes disponibles :
  windows.info        Informations système
  windows.pslist      Liste des processus
  windows.pstree      Arbre des processus
  windows.netscan     Connexions réseau
  windows.malfind     Détection d'injections mémoire
  windows.dlllist     DLLs chargées (--pid recommandé)
  windows.handles     Handles ouverts (--pid recommandé)
  windows.dumpfiles   Extraire fichiers (--pid requis)
  windows.strings     Extraire chaînes (--pid optionnel)
  windows.registry    Artefacts registre (persistence)

Exemples :
  python vol_analyzer.py -f memory.dmp windows.pslist
  python vol_analyzer.py -f memory.dmp windows.malfind --pid 6847
  python vol_analyzer.py -f memory.dmp windows.dumpfiles --pid 6847 --output ./extracted
        """)

    parser.add_argument("-f", "--file", required=True, help="Chemin vers le fichier memory.dmp")
    parser.add_argument("command", nargs="?", help="Commande d'analyse à exécuter")
    parser.add_argument("--pid", type=int, help="Filtrer par PID")
    parser.add_argument("--output", "-o", help="Répertoire de sortie (pour dumpfiles)")

    args = parser.parse_args()

    banner()

    if not os.path.exists(args.file):
        print(colored(f"[!] Fichier non trouvé : {args.file}", Colors.RED))
        sys.exit(1)

    reader = MemoryDumpReader(args.file)

    if not args.command:
        print(colored("  Commandes disponibles :", Colors.BOLD))
        print()
        for cmd_name in COMMANDS:
            print(f"    {cmd_name}")
        print()
        print(f"  Usage : python {sys.argv[0]} -f <dump> <commande> [--pid <PID>]")
        print()
        return

    cmd_func = COMMANDS.get(args.command)
    if not cmd_func:
        print(colored(f"[!] Commande inconnue : {args.command}", Colors.RED))
        print(f"    Commandes disponibles : {', '.join(COMMANDS.keys())}")
        sys.exit(1)

    cmd_func(reader, args)


if __name__ == "__main__":
    main()

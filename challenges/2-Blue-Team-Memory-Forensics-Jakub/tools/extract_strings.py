#!/usr/bin/env python3
"""
=============================================================================
  Blue Team CTF – extract_strings.py
  Outil d'extraction de chaînes à partir d'un binaire extrait
=============================================================================
Usage :
  python extract_strings.py <fichier_binaire> [--min-len N] [--encoding ascii|unicode|both]
"""

import argparse
import os
import sys
import hashlib

class Colors:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"


# Mots-clés intéressants pour l'analyse forensique
KEYWORDS_CRITICAL = ["flag", "c2", "beacon", "exfil", "password", "secret", "key"]
KEYWORDS_SUSPICIOUS = [
    "cmd.exe", "powershell", "http", "https", "host:", "post", "get",
    ".dll", "virtual", "alloc", "create", "write", "thread", "inject",
    "pipe", "socket", "connect", "download", "upload", "encode", "decode",
    "xor", "encrypt", "decrypt", "base64", "shell", "exploit", "payload",
    "whoami", "ipconfig", "systeminfo", "net user", "tasklist",
    "registry", "currentversion\\run", "startup",
]
KEYWORDS_NETWORK = [
    "mozilla", "user-agent", "content-type", "application",
    "tcp", "udp", "port", "listen", "bind", "recv", "send",
]


def extract_ascii_strings(data, min_len=4):
    """Extrait les chaînes ASCII imprimables."""
    strings = []
    current = ""
    offset = 0
    start_offset = 0

    for i, byte in enumerate(data):
        if 32 <= byte < 127:
            if not current:
                start_offset = i
            current += chr(byte)
        else:
            if len(current) >= min_len:
                strings.append((start_offset, current))
            current = ""

    if len(current) >= min_len:
        strings.append((start_offset, current))

    return strings


def extract_unicode_strings(data, min_len=4):
    """Extrait les chaînes Unicode (UTF-16LE)."""
    strings = []
    current = ""
    start_offset = 0

    i = 0
    while i < len(data) - 1:
        # UTF-16LE : byte significatif + 0x00
        if 32 <= data[i] < 127 and data[i+1] == 0:
            if not current:
                start_offset = i
            current += chr(data[i])
            i += 2
        else:
            if len(current) >= min_len:
                strings.append((start_offset, current))
            current = ""
            i += 1

    if len(current) >= min_len:
        strings.append((start_offset, current))

    return strings


def classify_string(s):
    """Classifie une chaîne par niveau de suspicion."""
    s_lower = s.lower()

    for kw in KEYWORDS_CRITICAL:
        if kw in s_lower:
            return "CRITICAL", Colors.RED

    for kw in KEYWORDS_SUSPICIOUS:
        if kw in s_lower:
            return "SUSPICIOUS", Colors.YELLOW

    for kw in KEYWORDS_NETWORK:
        if kw in s_lower:
            return "NETWORK", Colors.CYAN

    return "NORMAL", Colors.RESET


def compute_hashes(data):
    """Calcule les hashes du fichier."""
    return {
        "MD5":    hashlib.md5(data).hexdigest(),
        "SHA1":   hashlib.sha1(data).hexdigest(),
        "SHA256": hashlib.sha256(data).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser(description="Extracteur de chaînes pour analyse forensique")
    parser.add_argument("file", help="Fichier binaire à analyser")
    parser.add_argument("--min-len", type=int, default=4, help="Longueur minimale des chaînes (défaut: 4)")
    parser.add_argument("--encoding", choices=["ascii", "unicode", "both"], default="both",
                        help="Type d'encodage à chercher (défaut: both)")
    parser.add_argument("--no-color", action="store_true", help="Désactiver les couleurs")
    parser.add_argument("--output", "-o", help="Fichier de sortie pour les résultats")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"[!] Fichier non trouvé : {args.file}")
        sys.exit(1)

    with open(args.file, "rb") as f:
        data = f.read()

    # Si le fichier est encodé en base64 (fallback AV), le décoder
    if args.file.endswith(".b64"):
        import base64
        try:
            data = base64.b64decode(data)
            print("  [i] Fichier base64 détecté, décodage automatique.")
        except Exception:
            pass

    print(f"\n{'='*60}")
    print(f"  🔍 Analyse de chaînes : {os.path.basename(args.file)}")
    print(f"{'='*60}\n")

    # Hashes
    hashes = compute_hashes(data)
    print(f"  Taille :  {len(data):,} octets")
    for name, value in hashes.items():
        print(f"  {name}:     {value}")
    print()

    # Extraction
    all_strings = []

    if args.encoding in ("ascii", "both"):
        ascii_strings = extract_ascii_strings(data, args.min_len)
        for offset, s in ascii_strings:
            all_strings.append((offset, s, "ASCII"))

    if args.encoding in ("unicode", "both"):
        unicode_strings = extract_unicode_strings(data, args.min_len)
        for offset, s in unicode_strings:
            all_strings.append((offset, s, "UNICODE"))

    # Trier par offset
    all_strings.sort(key=lambda x: x[0])

    # Dédupliquer (garder la première occurrence)
    seen = set()
    unique_strings = []
    for offset, s, enc in all_strings:
        if s not in seen:
            seen.add(s)
            unique_strings.append((offset, s, enc))

    # Affichage
    print(f"  {'#':<6} {'Offset':<12} {'Enc':<8} {'Tag':<12} {'String'}")
    print(f"  {'─'*6} {'─'*12} {'─'*8} {'─'*12} {'─'*50}")

    output_lines = []
    critical_count = 0
    suspicious_count = 0

    for i, (offset, s, enc) in enumerate(unique_strings):
        tag, color = classify_string(s)

        if tag == "CRITICAL":
            critical_count += 1
        elif tag in ("SUSPICIOUS", "NETWORK"):
            suspicious_count += 1

        if args.no_color:
            line = f"  {i+1:<6} 0x{offset:08x}  {enc:<8} {tag:<12} {s}"
        else:
            tag_display = f"{color}{tag}{Colors.RESET}"
            s_display = f"{color}{s}{Colors.RESET}" if tag != "NORMAL" else s
            line = f"  {i+1:<6} 0x{offset:08x}  {enc:<8} {tag_display:<24} {s_display}"

        print(line)
        output_lines.append(f"{i+1}\t0x{offset:08x}\t{enc}\t{tag}\t{s}")

    # Résumé
    print(f"\n{'='*60}")
    print(f"  📊 Résumé")
    print(f"{'='*60}")
    print(f"  Total chaînes :         {len(unique_strings)}")
    print(f"  Chaînes CRITICAL :      {Colors.RED}{critical_count}{Colors.RESET}")
    print(f"  Chaînes SUSPICIOUS :    {Colors.YELLOW}{suspicious_count}{Colors.RESET}")
    print()

    if critical_count > 0:
        print(f"  {Colors.RED}[!] Des chaînes CRITIQUES ont été trouvées ! Examinez-les attentivement.{Colors.RESET}")
    if suspicious_count > 0:
        print(f"  {Colors.YELLOW}[!] Des chaînes SUSPECTES indiquent un comportement malveillant.{Colors.RESET}")
    print()

    # Sauvegarde optionnelle
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(f"# Strings analysis: {os.path.basename(args.file)}\n")
            f.write(f"# Size: {len(data)} bytes\n")
            for name, value in hashes.items():
                f.write(f"# {name}: {value}\n")
            f.write(f"# Total strings: {len(unique_strings)}\n\n")
            f.write("Index\tOffset\tEncoding\tTag\tString\n")
            for line in output_lines:
                f.write(line + "\n")
        print(f"  [✓] Résultats sauvegardés dans : {args.output}")
        print()


if __name__ == "__main__":
    main()

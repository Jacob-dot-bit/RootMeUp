#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =====================================================================
#  gen_secret.py -- generateur mainteneur (execute au build Docker)
#
#  Genere secret.h (licence XORee) + flag1.txt / flag2.txt.
#
#  Les valeurs sensibles (licence, flags) ne sont PLUS ecrites en dur ici :
#  elles proviennent, par ordre de priorite,
#    1. des variables d'environnement (ex: passees en --build-arg),
#    2. du fichier `challenge.env` place a cote de ce script (gitignore),
#    3. a defaut, de placeholders inoffensifs (le build reussit mais les
#       flags ne sont pas les vrais -> un avertissement est affiche).
#
#  Voir challenge.env.example pour le modele a copier en challenge.env.
# =====================================================================

import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = os.path.join(SCRIPT_DIR, "challenge.env")

# Placeholders : PAS les vrais flags. Le build reste fonctionnel pour les
# tests, mais ces valeurs doivent etre remplacees via challenge.env / build-arg.
PLACEHOLDERS = {
    "LICENSE": "CHANGEME_license_a_definir",
    "FLAG1":   "RM{PLACEHOLDER_definir_dans_challenge_env}",
    "FLAG2":   "RM{PLACEHOLDER_definir_dans_challenge_env}",
    "XOR_KEY": "0x5c",
}


def load_env_file(path):
    """Parse simple d'un fichier KEY=VALUE (lignes vides / # ignorees)."""
    values = {}
    if not os.path.isfile(path):
        return values
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            values[key.strip()] = val.strip().strip('"').strip("'")
    return values


def resolve(name, file_values):
    """env var (non vide) > challenge.env > placeholder."""
    env = os.environ.get(name)
    if env:
        return env, "env"
    if file_values.get(name):
        return file_values[name], "challenge.env"
    return PLACEHOLDERS[name], "placeholder"


def main():
    file_values = load_env_file(ENV_FILE)

    license_, s1 = resolve("LICENSE", file_values)
    flag1, s2 = resolve("FLAG1", file_values)
    flag2, s3 = resolve("FLAG2", file_values)
    xor_raw, _ = resolve("XOR_KEY", file_values)
    xor_key = int(xor_raw, 0) & 0xFF  # accepte 0x.. ou decimal

    if "placeholder" in (s1, s2, s3):
        print("[gen_secret] /!\\ ATTENTION : valeurs par defaut (placeholders) "
              "utilisees. Definissez challenge.env ou passez les build-args "
              "(LICENSE, FLAG1, FLAG2). Voir challenge.env.example.",
              file=sys.stderr)

    enc = ", ".join(str(b ^ xor_key) for b in license_.encode())
    with open("secret.h", "w") as f:
        f.write("#ifndef SECRET_H\n#define SECRET_H\n")
        f.write("/* Genere par gen_secret.py -- ne pas editer a la main. */\n")
        f.write(f"#define XOR_KEY 0x{xor_key:02x}\n")
        f.write(f"#define LICENSE_LEN {len(license_)}\n")
        f.write(f"static const unsigned char LICENSE_ENC[] = {{ {enc} }};\n")
        f.write("#endif\n")

    with open("flag1.txt", "w") as f:
        f.write(flag1 + "\n")
    with open("flag2.txt", "w") as f:
        f.write(flag2 + "\n")

    print(f"[gen_secret] secret.h + flags generes "
          f"(licence:{s1}, flag1:{s2}, flag2:{s3}).")


if __name__ == "__main__":
    main()

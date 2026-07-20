#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =====================================================================
#  gen_secret.py -- generateur mainteneur (execute au build Docker)
#  /!\ SPOILER : contient la licence et les flags en clair.
#
#  Genere :
#    - secret.h  : la licence XORee (importee par vault.c)
#    - flag1.txt : flag de l'etape reverse
#    - flag2.txt : flag de l'etape exploitation
#
#  Pour changer les flags/la licence, modifiez les constantes ci-dessous
#  puis rebuildez l'image. Rien de sensible n'est ecrit dans le binaire.
# =====================================================================

LICENSE = "unl0ck_th3_v4ult"          # cle attendue par check_license()
XOR_KEY = 0x5C                        # cle de XOR mono-octet
FLAG1   = "RM{r3v3rs3_l3_x0r_c0mm3_un_pr0}"
FLAG2   = "RM{r3t2w1n_l4_v4ult_3st_0uv3rt3}"


def main():
    enc = ", ".join(str(b ^ XOR_KEY) for b in LICENSE.encode())
    with open("secret.h", "w") as f:
        f.write("#ifndef SECRET_H\n#define SECRET_H\n")
        f.write("/* Genere par gen_secret.py -- ne pas editer a la main. */\n")
        f.write(f"#define XOR_KEY 0x{XOR_KEY:02x}\n")
        f.write(f"#define LICENSE_LEN {len(LICENSE)}\n")
        f.write(f"static const unsigned char LICENSE_ENC[] = {{ {enc} }};\n")
        f.write("#endif\n")

    with open("flag1.txt", "w") as f:
        f.write(FLAG1 + "\n")
    with open("flag2.txt", "w") as f:
        f.write(FLAG2 + "\n")

    print("[gen_secret] secret.h, flag1.txt, flag2.txt generes.")


if __name__ == "__main__":
    main()

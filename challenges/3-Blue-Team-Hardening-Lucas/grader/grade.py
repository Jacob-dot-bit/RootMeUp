#!/usr/bin/env python3
# =============================================================================
#  grade.py  -  Valideur de durcissement CÔTÉ SERVEUR (CLI admin)
#
#  ⚠️ S'exécute sur le SERVEUR (hôte CTFd / poste admin), jamais dans le
#  conteneur. Détient les flags (via checks.py). Inspecte l'état d'une instance
#  en local (--target, tests) ou à distance (--ssh) et ne révèle un flag que si
#  le correctif est réellement appliqué.
#
#  Usage :
#     python3 grade.py --target /chemin/rootfs           # test local
#     python3 grade.py --ssh root@10.0.0.5 -p 2222       # instance distante
#     python3 grade.py --ssh ... --task 1                # un seul flag
#     python3 grade.py --ssh ... --score-only            # juste X/10
# =============================================================================
import argparse
import sys

from checks import FLAGS, LABELS, LocalInspector, SSHInspector, evaluate


def main():
    ap = argparse.ArgumentParser(description="Valideur de durcissement (serveur)")
    ap.add_argument("--target", help="préfixe de chemin local (tests)")
    ap.add_argument("--ssh", help="cible SSH, ex: root@10.0.0.5")
    ap.add_argument("-p", "--port", type=int, default=22, help="port SSH")
    ap.add_argument("--task", type=int, metavar="N", help="ne valider qu'une tâche (1-10)")
    ap.add_argument("--score-only", action="store_true", help="n'affiche que X/10")
    args = ap.parse_args()

    insp = SSHInspector(args.ssh, args.port) if args.ssh else LocalInspector(args.target)
    ok = evaluate(insp)

    if args.task:
        n = args.task
        if n not in FLAGS:
            print("Tâche inconnue (1 à 10)."); sys.exit(2)
        if n in ok:
            print(f"[OK] {n}. {LABELS[n]} -> {FLAGS[n]}"); sys.exit(0)
        print(f"[KO] {n}. {LABELS[n]} : non durci, flag non délivré."); sys.exit(1)

    if args.score_only:
        print(f"{len(ok)}/10"); sys.exit(0 if len(ok) == 10 else 1)

    print("=" * 60)
    print(" VALIDATION DU DURCISSEMENT - srv-legacy01 (côté serveur)")
    print("=" * 60)
    for i in range(1, 11):
        if i in ok:
            print(f" [OK]   {i:>2}. {LABELS[i]:<34} -> {FLAGS[i]}")
        else:
            print(f" [KO]   {i:>2}. {LABELS[i]:<34} (non durci, flag non délivré)")
    print("-" * 60)
    print(f" Score : {len(ok)}/10 correctifs validés")
    print("=" * 60)
    sys.exit(0 if len(ok) == 10 else 2)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
=============================================================================
  Blue Team CTF – Validation du flag et scoring
=============================================================================
Valide les réponses du joueur et calcule un score.
"""

import hashlib
import sys

# ─── Hashes SHA256 des réponses attendues ─────────────────────────────────────
# Les réponses en clair ne sont PAS stockées ici pour éviter le spoil.
# Ces hashes ont été générés lors de la création du challenge.

EXPECTED_HASHES = {
    "pid":          "890ebdf964b651bc670b2001f32aad8eb1c0e9704f7857b4961fd0a602eed83b",
    "process_name": "47a648b1bbc9399b36e7189ea5ee0f855262c39c5dff523bc60eec2bc89fd963",
    "c2_ip":        "4e0a24277c461cb7a6b904173aabf898ba90cf9f5832a1a54c5258a6ea26c08b",
    "c2_domain":    "b6bd3f76cc36838799e6969e675143ffa8a738743b613a8e67400cf255d11163",
    "c2_port":      "79f06f8fde333461739f220090a23cb2a79f6d714bee100d0e4b4af249294619",
    "flag":         "adbace5b3008f4f51eb858fa0ff6ac58923b88da172a4f86902079bb9469abef",
}

SCORING = {
    "pid":          15,
    "process_name": 15,
    "c2_ip":        20,
    "c2_domain":    15,
    "c2_port":      10,
    "flag":         25,
}

TOTAL_MAX = sum(SCORING.values())


def validate_answer(key, answer):
    """Valide une réponse individuelle."""
    expected_hash = EXPECTED_HASHES.get(key)
    if not expected_hash:
        return False
    return hashlib.sha256(answer.strip().encode()).hexdigest() == expected_hash


def main():
    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║        🔵 Blue Team CTF – Validation des Réponses       ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()

    score = 0
    results = {}

    questions = [
        ("pid",          "PID du processus malveillant"),
        ("process_name", "Nom de l'exécutable malveillant"),
        ("c2_ip",        "Adresse IP du serveur C2"),
        ("c2_domain",    "Nom de domaine du C2"),
        ("c2_port",      "Port principal du C2"),
        ("flag",         "Flag complet (format: blue{...})"),
    ]

    for key, question in questions:
        answer = input(f"  ❓ {question} : ").strip()
        if validate_answer(key, answer):
            points = SCORING[key]
            score += points
            results[key] = ("✅", points)
            print(f"     ✅ Correct ! (+{points} pts)")
        else:
            results[key] = ("❌", 0)
            print(f"     ❌ Incorrect.")
        print()

    # Résumé
    print("═" * 58)
    print(f"  📊 RÉSULTATS")
    print("═" * 58)
    print()
    print(f"  {'Question':<40} {'Résultat':<10} {'Points'}")
    print(f"  {'─'*40} {'─'*10} {'─'*8}")

    for key, question in questions:
        status, points = results[key]
        print(f"  {question:<40} {status:<10} {points}/{SCORING[key]}")

    print()
    print(f"  {'─'*58}")
    pct = (score / TOTAL_MAX) * 100

    if pct == 100:
        grade = "🏆 PARFAIT"
    elif pct >= 75:
        grade = "🥈 EXCELLENT"
    elif pct >= 50:
        grade = "🥉 BON"
    elif pct >= 25:
        grade = "📝 PASSABLE"
    else:
        grade = "💀 À RETRAVAILLER"

    print(f"  SCORE FINAL : {score}/{TOTAL_MAX} ({pct:.0f}%) – {grade}")
    print()

    if pct < 100:
        print("  💡 Indices :")
        if results.get("pid", ("", 0))[1] == 0:
            print("     - Cherchez un processus avec un nom inhabituel dans pslist")
        if results.get("process_name", ("", 0))[1] == 0:
            print("     - Le nom ressemble à un processus système mais n'en est pas un")
        if results.get("c2_ip", ("", 0))[1] == 0:
            print("     - Utilisez netscan pour voir les connexions réseau")
        if results.get("c2_domain", ("", 0))[1] == 0:
            print("     - Extrayez les strings du binaire malveillant")
        if results.get("c2_port", ("", 0))[1] == 0:
            print("     - Regardez le port distant dans netscan")
        if results.get("flag", ("", 0))[1] == 0:
            print("     - Le flag est caché dans la configuration du malware")
        print()


if __name__ == "__main__":
    main()

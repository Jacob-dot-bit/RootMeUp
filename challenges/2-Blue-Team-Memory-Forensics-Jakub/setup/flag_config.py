#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =====================================================================
#  Résolution du flag du challenge (rotation hors dépôt public).
#  Priorité : variable d'env FLAG > setup/challenge.env > placeholder.
#  Le flag réel n'est donc jamais committé (challenge.env est gitignoré).
# =====================================================================

import os

_PLACEHOLDER = "blue{PLACEHOLDER_definir_dans_challenge_env}"


def resolve_flag():
    env = os.environ.get("FLAG")
    if env:
        return env
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "challenge.env")
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("FLAG="):
                    return line[len("FLAG="):].strip().strip('"').strip("'")
    return _PLACEHOLDER

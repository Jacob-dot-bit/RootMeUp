# =============================================================================
#  Blue Team CTF – Memory Forensics Challenge (Container)
# =============================================================================
#  Stage 1 : Génère le dump mémoire et le PCAP
#  Stage 2 : Image légère avec uniquement les outils d'analyse + les fichiers
# =============================================================================

# ── Stage 1 : Builder (génération des artefacts) ─────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Copier les scripts de génération
COPY setup/ ./setup/

# Installer les dépendances de génération
RUN pip install --no-cache-dir -r setup/requirements.txt

# Générer le dump mémoire et le PCAP
RUN python setup/generate_challenge.py && \
    python setup/generate_pcap.py


# ── Stage 2 : Image finale (challenge) ───────────────────────────────────────
FROM python:3.11-slim

LABEL maintainer="Jakub – ESGI Projet Annuel 2026"
LABEL description="Blue Team CTF – Mémoire et Analyse de Malware"

# Empêcher Python de bufferiser stdout/stderr
ENV PYTHONUNBUFFERED=1
ENV TERM=xterm-256color

WORKDIR /challenge

# Copier les artefacts générés depuis le builder
COPY --from=builder /build/challenge/ ./challenge/

# Copier les outils d'analyse (accessibles au joueur)
COPY tools/ ./tools/

# Copier le template de rapport
COPY report/ ./report/

# Copier le script de validation (le joueur peut valider ses réponses)
COPY solution/validate_flag.py ./solution/validate_flag.py

# Copier le README
COPY README.md ./README.md

# Copier le script d'accueil
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Créer un utilisateur non-root pour le joueur
RUN useradd -m -s /bin/bash analyst && \
    chown -R analyst:analyst /challenge

# Installer les outils utiles pour l'analyse
RUN apt-get update && apt-get install -y --no-install-recommends \
    less \
    nano \
    vim-tiny \
    xxd \
    file \
    && rm -rf /var/lib/apt/lists/*

USER analyst

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["/bin/bash"]

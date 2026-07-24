# =============================================================================
#  Blue Team CTF – Mémoire & Analyse de Malware (environnement d'analyse SSH)
# =============================================================================
#  Stage 1 : génère le dump mémoire + le PCAP (flag lu depuis challenge.env)
#  Stage 2 : boîte d'analyse accessible en SSH — dump + outils déjà en place,
#            le joueur se connecte et analyse dedans (rien à installer chez lui)
# =============================================================================

# ── Stage 1 : Builder (génération des artefacts) ─────────────────────────────
FROM python:3.11-slim AS builder
WORKDIR /build
COPY setup/ ./setup/
RUN pip install --no-cache-dir -r setup/requirements.txt
RUN python setup/generate_challenge.py && python setup/generate_pcap.py


# ── Stage 2 : Boîte d'analyse SSH ────────────────────────────────────────────
FROM python:3.11-slim

LABEL maintainer="Jakub – ESGI Projet Annuel 2026"
LABEL description="Blue Team CTF – Mémoire et Analyse de Malware (SSH)"
ENV PYTHONUNBUFFERED=1

# Serveur SSH + petits utilitaires d'analyse (les outils Python n'ont besoin
# que de la stdlib, déjà présente).
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server less nano vim-tiny xxd file && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /run/sshd && ssh-keygen -A

# Utilisateur joueur (identifiants communiqués dans l'énoncé CTFd).
# Pas de root en SSH ; authentification par mot de passe autorisée.
RUN useradd -m -s /bin/bash analyst && echo 'analyst:forensics' | chpasswd && \
    sed -i 's/#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Environnement d'analyse dans le home du joueur
WORKDIR /home/analyst
COPY --from=builder /build/challenge/ ./
COPY tools/vol_analyzer.py tools/extract_strings.py ./
COPY solution/validate_flag.py ./check_flag.py
COPY --from=builder /build/valout/flag.sha256 ./flag.sha256
COPY mission.txt /etc/motd
RUN chown -R analyst:analyst /home/analyst

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]

# =============================================================================
#  Blue Team CTF - Hardening - "Operation IRON GATE"
#  Serveur Linux volontairement mal configure, accessible via un TERMINAL WEB
#  (ttyd) sur le port 8000 assigne dynamiquement par CTFd.
#  Le joueur durcit le serveur ; la commande `audit` revele un flag par
#  correctif valide.
#
#  Build MULTI-STAGE : le verificateur est compile en binaire (symboles
#  supprimes, flags XOR-obfusques). L'image finale ne contient NI le code
#  source NI aucun flag en clair -> la triche par `cat`/`strings` echoue.
# =============================================================================

# ----------------------------- STAGE 1 : builder -----------------------------
FROM debian:12-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
COPY audit/checker.c /build/checker.c
# -s : strip des symboles ; -O2 : optimisation (rend le reverse plus penible)
RUN gcc -O2 -s -o /build/checker /build/checker.c

# ----------------------------- STAGE 2 : final -------------------------------
FROM debian:12-slim

LABEL maintainer="Lucas - ESGI Projet Annuel 2026" \
      challenge="Blue Team - Hardening" \
      scenario="Operation IRON GATE"

ENV DEBIAN_FRONTEND=noninteractive

# Outils dont le joueur a besoin pour administrer / durcir le serveur
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash sudo coreutils util-linux login procps iproute2 grep sed gawk \
        vim nano less cron passwd libpam-modules dos2unix \
        openssh-server curl ca-certificates supervisor \
    && rm -rf /var/lib/apt/lists/*

# Terminal web ttyd (binaire statique officiel)
RUN curl -fsSL -o /usr/local/bin/ttyd \
        https://github.com/tsl0922/ttyd/releases/download/1.7.7/ttyd.x86_64 \
    && chmod +x /usr/local/bin/ttyd

# --- Verificateur compile (root only, aucun flag en clair) -------------------
RUN mkdir -p /opt/audit
COPY --from=builder /build/checker /opt/audit/checker
RUN chmod 700 /opt/audit/checker && chown root:root /opt/audit/checker

# Commande `audit` accessible au joueur (execute le checker en root via sudo)
RUN printf '#!/bin/bash\nexec sudo /opt/audit/checker "$@"\n' > /usr/local/bin/audit \
    && chmod 755 /usr/local/bin/audit

# Commande `getflag` : client qui reclame un flag au serveur de validation.
# NE CONTIENT AUCUN FLAG. URL du grader configurable via -e GRADER_URL=...
ENV GRADER_URL="http://host.docker.internal:9000"
COPY setup/getflag /usr/local/bin/getflag
RUN dos2unix /usr/local/bin/getflag && chmod 755 /usr/local/bin/getflag

# --- Mise en place de l'environnement vulnerable au BUILD --------------------
COPY setup/harden_setup.sh /opt/setup/harden_setup.sh
RUN dos2unix /opt/setup/harden_setup.sh && bash /opt/setup/harden_setup.sh

# Orchestration
COPY supervisord.conf     /etc/supervisor/conf.d/challenge.conf
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN dos2unix /etc/supervisor/conf.d/challenge.conf /usr/local/bin/docker-entrypoint.sh \
    && chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --retries=5 \
    CMD curl -fsS http://127.0.0.1:8000/ >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/challenge.conf"]

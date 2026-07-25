# =============================================================================
# Meridian Capital - Operation SILENT LEDGER
# Red Team post-exploitation CTF instance (single container, 10 flags)
#
# Aucune option de lancement requise : un simple `docker run -p ...:22 <image>`
# suffit (pas de --cap-add, pas de --privileged).
#
# DESIGN: the privilege chain is strictly monotonic (one lateral move per step,
# root only at the very last system step via the orchestrator RCE, flag 8 lives
# only in the orchestrator's memory). See docs/ARCHITECTURE.md.
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: compile the SUID "logviewer" binary (flag 6, SUID svc_orch)
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
COPY challenge/logviewer.c /src/logviewer.c
RUN mkdir -p /out && gcc -Wall -o /out/logviewer /src/logviewer.c

# ---------------------------------------------------------------------------
# Stage 2: bake the encrypted loot (vault.zip / final.gpg / pin.hash) so the
# plaintext flags 9/10 never exist inside the final image layers.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS secrets
RUN apt-get update && apt-get install -y --no-install-recommends zip gnupg \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /secrets
COPY challenge/flag9.txt challenge/decoy_customers.csv ./
# F9 loot: zip protected with a weak, rockyou.txt-crackable password
RUN zip -P "iloveyou" vault.zip flag9.txt decoy_customers.csv \
    && rm flag9.txt decoy_customers.csv

COPY challenge/flag10.txt ./
# F10 loot: symmetrically GPG-encrypted with a 6-digit numeric PIN
RUN gpg --batch --yes --pinentry-mode loopback --passphrase "482913" \
        --cipher-algo AES256 --symmetric --output final.gpg flag10.txt \
    && printf '482913' | sha256sum | awk '{print $1}' > pin.hash \
    && rm flag10.txt

# ---------------------------------------------------------------------------
# Stage 3: final runtime image
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server sudo cron python3 procps \
        zip unzip gnupg less nano binutils strace gdb file \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/run/sshd /opt/meridian /opt/scripts /var/log/meridian \
               /root/vault /root/.encrypted

# --- users & groups -----------------------------------------------------
# Chain of accounts: j.martin -> svc_backup -> r.dubois -> app_agent
#                    -> svc_orch -> (root, only via the orchestrator)
# 'orch' group lets app_agent EXECUTE the SUID-svc_orch logviewer (flag 6).
RUN groupadd orch \
    && useradd -m -s /bin/bash j.martin \
    && useradd -m -s /bin/bash svc_backup \
    && useradd -m -s /bin/bash r.dubois \
    && useradd -m -s /bin/bash -G orch app_agent \
    && useradd -m -s /bin/bash svc_orch \
    && echo "j.martin:Welcome2024!"        | chpasswd \
    && echo "svc_backup:B4ckupSvc_2023!"   | chpasswd \
    && echo "r.dubois:An4lyst#Secure99"    | chpasswd \
    && passwd -l app_agent \
    && passwd -l svc_orch \
    && passwd -l root

# --- F1: recon (j.martin) --------------------------------------------------
COPY challenge/welcome_note.txt /home/j.martin/welcome_note.txt
COPY challenge/bash_history_jmartin /home/j.martin/.bash_history

# --- F2: filesystem enumeration (world-readable backups) -------------------
COPY challenge/app_config.bak /var/backups/app_config.bak
COPY challenge/decoy_website_2019.bak /var/backups/website_2019.bak
COPY challenge/decoy_db_dump_old.bak /var/backups/db_dump_old.bak

# --- F3: credential harvesting -> svc_backup -------------------------------
COPY challenge/flag3.txt /home/svc_backup/flag3.txt

# --- F4: writable cron running as r.dubois (lateral svc_backup -> r.dubois) --
COPY challenge/cleanup.sh /opt/scripts/cleanup.sh
COPY challenge/cron_meridian /etc/cron.d/meridian
# r.dubois' private password reminder (600 r.dubois): only reachable by
# executing code AS r.dubois via the cron -> holds flag 4.
COPY challenge/r_dubois_creds.txt /home/r.dubois/.password_reminder

# --- F5: sudo misconfiguration (lateral r.dubois -> app_agent) -------------
COPY challenge/sudoers_rdubois /etc/sudoers.d/r_dubois
COPY challenge/flag5.txt /home/app_agent/flag5.txt

# --- F6: SUID-svc_orch logviewer (lateral app_agent -> svc_orch) -----------
COPY --from=builder /out/logviewer /usr/local/bin/logviewer
RUN echo "app started ok" > /var/log/meridian/app.log
COPY challenge/flag6.txt /home/svc_orch/flag6.txt

# --- F7: post-compromission looting (svc_orch reste le compte) -------------
# Aucune capability requise (donc AUCUN --cap-add au run). Le token de
# l'orchestrateur est stocke EN CLAIR dans la config locale de l'agent, lisible
# uniquement une fois svc_orch compromis (fichier 600 svc_orch). Butin classique.
RUN mkdir -p /home/svc_orch/.fleet-agent
COPY challenge/agent_config.ini /home/svc_orch/.fleet-agent/config.ini
# Le daemon (root) lit sa copie du token depuis un fichier root-only :
COPY challenge/orchestrator_token.txt /root/.orchestrator_token

# --- F8: orchestrator daemon (insecure deserialization -> root) ------------
# flag 8 is copied to a root-only dotfile; the daemon loads it into memory at
# startup and DELETES the file, so only in-process RCE can recover it.
COPY challenge/orchestrator.py /opt/meridian/orchestrator.py
COPY challenge/flag8.txt /root/vault/.flag8

# --- F9 / F10: encrypted vault + final PIN-protected archive ----------------
COPY --from=secrets /secrets/vault.zip /root/vault/vault.zip
COPY --from=secrets /secrets/final.gpg /root/.encrypted/final.gpg
COPY --from=secrets /secrets/pin.hash  /root/.encrypted/pin.hash

# --- permissions ---------------------------------------------------------
RUN chown j.martin:j.martin /home/j.martin/welcome_note.txt /home/j.martin/.bash_history \
    && chmod 600 /home/j.martin/.bash_history \
    && chmod 644 /var/backups/*.bak \
    && chown svc_backup:svc_backup /home/svc_backup/flag3.txt && chmod 600 /home/svc_backup/flag3.txt \
    && chown root:svc_backup /opt/scripts/cleanup.sh && chmod 664 /opt/scripts/cleanup.sh \
    && chown root:root /etc/cron.d/meridian && chmod 644 /etc/cron.d/meridian \
    && chown r.dubois:r.dubois /home/r.dubois/.password_reminder && chmod 600 /home/r.dubois/.password_reminder \
    && chown app_agent:app_agent /home/app_agent/flag5.txt && chmod 600 /home/app_agent/flag5.txt \
    && chmod 440 /etc/sudoers.d/r_dubois \
    && chown svc_orch:orch /usr/local/bin/logviewer && chmod 4750 /usr/local/bin/logviewer \
    && chmod 644 /var/log/meridian/app.log \
    && chown svc_orch:svc_orch /home/svc_orch/flag6.txt && chmod 600 /home/svc_orch/flag6.txt \
    && chown -R svc_orch:svc_orch /home/svc_orch/.fleet-agent \
    && chmod 700 /home/svc_orch/.fleet-agent && chmod 600 /home/svc_orch/.fleet-agent/config.ini \
    && chown root:root /root/.orchestrator_token && chmod 600 /root/.orchestrator_token \
    && chown root:root /opt/meridian/orchestrator.py /root/vault/.flag8 /root/vault/vault.zip \
    && chmod 600 /opt/meridian/orchestrator.py /root/vault/.flag8 /root/vault/vault.zip \
    && chown root:root /root/.encrypted/final.gpg /root/.encrypted/pin.hash \
    && chmod 600 /root/.encrypted/final.gpg /root/.encrypted/pin.hash \
    && chmod 700 /root/vault /root/.encrypted

# --- SSH config ---------------------------------------------------------
# Only the three human accounts can log in over SSH. Service accounts
# (app_agent, svc_orch) are locked and reachable only via privilege escalation.
RUN sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/^AllowUsers.*//' /etc/ssh/sshd_config \
    && echo "AllowUsers j.martin svc_backup r.dubois" >> /etc/ssh/sshd_config \
    && echo "Banner /etc/motd_banner" >> /etc/ssh/sshd_config
COPY challenge/motd /etc/motd_banner

COPY challenge/entrypoint.sh /entrypoint.sh
# Normaliser les fins de ligne (CRLF Windows -> LF) sur les scripts/configs
# exécutés, sinon le shebang casse (`exec: no such file or directory`).
RUN sed -i 's/\r$//' /entrypoint.sh /opt/scripts/cleanup.sh \
        /opt/meridian/orchestrator.py /etc/cron.d/meridian /etc/sudoers.d/r_dubois \
    && chmod +x /entrypoint.sh /opt/scripts/cleanup.sh

EXPOSE 22
CMD ["/entrypoint.sh"]

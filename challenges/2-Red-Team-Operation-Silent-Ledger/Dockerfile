# =============================================================================
# Meridian Capital - Operation SILENT LEDGER
# Red Team post-exploitation CTF instance (single container, 10 flags)
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: compile the vulnerable SUID "logviewer" binary (F5)
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
COPY challenge/logviewer.c /src/logviewer.c
RUN mkdir -p /out && gcc -Wall -o /out/logviewer /src/logviewer.c

# ---------------------------------------------------------------------------
# Stage 2: bake the encrypted loot (vault.zip / final.gpg / pin.hash) so the
# plaintext flags never exist inside the final image layers.
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
        openssh-server sudo cron python3 libcap2-bin procps \
        zip unzip gnupg less nano binutils strace gdb file \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/run/sshd /opt/meridian /opt/scripts /var/log/meridian \
               /root/creds /root/vault /root/.encrypted

# --- users & groups -----------------------------------------------------
RUN groupadd analysts \
    && useradd -m -s /bin/bash j.martin \
    && useradd -m -s /bin/bash svc_backup \
    && useradd -m -s /bin/bash -G analysts r.dubois \
    && useradd -m -s /bin/bash app_agent \
    && echo "j.martin:Welcome2024!"        | chpasswd \
    && echo "svc_backup:B4ckupSvc_2023!"   | chpasswd \
    && echo "r.dubois:An4lyst#Secure99"    | chpasswd \
    && passwd -l app_agent \
    && passwd -l root

# --- F1: recon ------------------------------------------------------------
COPY challenge/welcome_note.txt /home/j.martin/welcome_note.txt
COPY challenge/bash_history_jmartin /home/j.martin/.bash_history

# --- F2: filesystem enumeration -------------------------------------------
COPY challenge/app_config.bak /var/backups/app_config.bak
COPY challenge/decoy_website_2019.bak /var/backups/website_2019.bak
COPY challenge/decoy_db_dump_old.bak /var/backups/db_dump_old.bak

# --- F3: credential harvesting ---------------------------------------------
COPY challenge/flag3.txt /home/svc_backup/flag3.txt

# --- F4: cron privesc -------------------------------------------------------
COPY challenge/cleanup.sh /opt/scripts/cleanup.sh
COPY challenge/cron_meridian /etc/cron.d/meridian
COPY challenge/r_dubois_creds.txt /root/creds/r_dubois_password.txt

# --- F5: SUID binary ---------------------------------------------------------
COPY --from=builder /out/logviewer /usr/local/bin/logviewer
RUN echo "app started ok" > /var/log/meridian/app.log
COPY challenge/flag5.txt /root/flag5.txt

# --- F6: sudo misconfiguration -----------------------------------------------
COPY challenge/sudoers_rdubois /etc/sudoers.d/r_dubois
COPY challenge/flag6.txt /home/app_agent/flag6.txt

# --- F7: Linux capabilities ---------------------------------------------------
RUN cp /usr/bin/python3 /usr/local/bin/py-agent \
    && setcap cap_dac_read_search+ep /usr/local/bin/py-agent
COPY challenge/flag7.txt /root/flag7.txt
COPY challenge/readme_orchestrator.txt /root/README_orchestrator.txt
COPY challenge/orchestrator_token.txt /root/.orchestrator_token

# --- F8: custom orchestrator daemon (insecure deserialization) --------------
COPY challenge/orchestrator.py /opt/meridian/orchestrator.py
COPY challenge/flag8.txt /root/vault/flag8.txt

# --- F9 / F10: encrypted vault + final PIN-protected archive ----------------
COPY --from=secrets /secrets/vault.zip /root/vault/vault.zip
COPY --from=secrets /secrets/final.gpg /root/.encrypted/final.gpg
COPY --from=secrets /secrets/pin.hash  /root/.encrypted/pin.hash

# --- permissions ---------------------------------------------------------
RUN chown j.martin:j.martin /home/j.martin/welcome_note.txt /home/j.martin/.bash_history \
    && chmod 644 /var/backups/*.bak \
    && chown svc_backup:svc_backup /home/svc_backup/flag3.txt && chmod 600 /home/svc_backup/flag3.txt \
    && chown root:svc_backup /opt/scripts/cleanup.sh && chmod 664 /opt/scripts/cleanup.sh \
    && chmod 644 /etc/cron.d/meridian \
    && chown root:root /root/creds/r_dubois_password.txt && chmod 600 /root/creds/r_dubois_password.txt \
    && chown root:analysts /usr/local/bin/logviewer && chmod 4750 /usr/local/bin/logviewer \
    && chmod 644 /var/log/meridian/app.log \
    && chown root:root /root/flag5.txt && chmod 600 /root/flag5.txt \
    && chmod 440 /etc/sudoers.d/r_dubois \
    && chown app_agent:app_agent /home/app_agent/flag6.txt && chmod 600 /home/app_agent/flag6.txt \
    && chown root:root /usr/local/bin/py-agent && chmod 755 /usr/local/bin/py-agent \
    && chown root:root /root/flag7.txt /root/README_orchestrator.txt /root/.orchestrator_token \
    && chmod 600 /root/flag7.txt /root/.orchestrator_token && chmod 644 /root/README_orchestrator.txt \
    && chown root:root /root/vault/flag8.txt /root/vault/vault.zip \
    && chmod 600 /root/vault/flag8.txt /root/vault/vault.zip \
    && chown root:root /root/.encrypted/final.gpg /root/.encrypted/pin.hash \
    && chmod 600 /root/.encrypted/final.gpg /root/.encrypted/pin.hash \
    && chmod 600 /opt/meridian/orchestrator.py

# --- SSH config ---------------------------------------------------------
RUN sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/^AllowUsers.*//' /etc/ssh/sshd_config \
    && echo "AllowUsers j.martin svc_backup r.dubois" >> /etc/ssh/sshd_config \
    && echo "Banner /etc/motd_banner" >> /etc/ssh/sshd_config
COPY challenge/motd /etc/motd_banner

COPY challenge/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /opt/scripts/cleanup.sh

EXPOSE 22
CMD ["/entrypoint.sh"]

# VAULT-9 -- Red Team (reverse + exploitation binaire) -- BOÎTE SSH STAND-ALONE
#
# Modèle "environnement fourni" (comme le challenge Memory / pwn.college) :
#   - le joueur se connecte en SSH (compte 'hacker'),
#   - le binaire vulnérable + les outils (gdb, objdump, pwntools...) sont déjà là,
#   - le service vulnérable tourne EN LOCAL sous l'utilisateur 'vault' (seul à pouvoir
#     lire les flags) : le joueur doit l'EXPLOITER (nc localhost 9003), il ne peut PAS
#     simplement `cat` les flags.

# ---------- Étage 1 : build du binaire vulnérable ----------
FROM debian:12-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libc6-dev python3 && \
    rm -rf /var/lib/apt/lists/*

# Secrets fournis au build (priorité sur setup/challenge.env). Vides par défaut
# -> gen_secret.py utilise challenge.env ou des placeholders.
ARG LICENSE=""
ARG FLAG1=""
ARG FLAG2=""
ARG XOR_KEY=""

WORKDIR /build
COPY challenge/vault.c ./vault.c
COPY setup/ ./setup/
RUN LICENSE="$LICENSE" FLAG1="$FLAG1" FLAG2="$FLAG2" XOR_KEY="$XOR_KEY" \
        python3 setup/gen_secret.py && \
    gcc -fno-stack-protector -no-pie -fno-pie -O0 -w -o vault vault.c

# ---------- Étage 2 : boîte d'attaque SSH ----------
FROM debian:12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server socat \
        gcc gdb binutils file less nano procps \
        python3 python3-pip netcat-openbsd ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# pwntools : le joueur écrit son exploit sans rien installer chez lui.
RUN pip3 install --no-cache-dir --break-system-packages pwntools

# Configuration SSH (mot de passe, pas de root)
RUN mkdir -p /run/sshd && ssh-keygen -A && \
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

# 'vault' = utilisateur de service (possède les flags, exécute le binaire).
# 'hacker' = compte du joueur (mot de passe : vault9).
RUN useradd -m -s /usr/sbin/nologin vault && \
    useradd -m -s /bin/bash hacker && \
    echo 'hacker:vault9' | chpasswd

# Binaire + flags (depuis l'étage de build)
COPY --from=builder /build/vault /challenge/vault
COPY --from=builder /build/flag1.txt /build/flag2.txt /challenge/
# Le binaire est public (0555) ; les flags n'appartiennent QU'À 'vault' (0400) :
# le joueur 'hacker' ne peut pas les lire -> il doit exploiter le service.
RUN chown root:root /challenge/vault && chmod 0555 /challenge/vault && \
    chown vault:vault /challenge/flag1.txt /challenge/flag2.txt && \
    chmod 0400 /challenge/flag1.txt /challenge/flag2.txt && \
    cp /challenge/vault /home/hacker/vault && \
    chown hacker:hacker /home/hacker/vault && chmod 0555 /home/hacker/vault

COPY mission.txt /etc/motd
COPY docker-entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

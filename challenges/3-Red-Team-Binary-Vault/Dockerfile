# VAULT-9 -- Red Team 3 (reverse + exploitation binaire)
# Build : le binaire est compile sans protections modernes (no PIE,
# no stack canary) pour rendre le ret2win faisable en intermediaire.
FROM debian:12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc libc6-dev socat python3 && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /usr/sbin/nologin ctf

# Secrets fournis au build (priorite sur setup/challenge.env). Vides par
# defaut -> gen_secret.py utilise challenge.env ou des placeholders.
ARG LICENSE=""
ARG FLAG1=""
ARG FLAG2=""
ARG XOR_KEY=""

WORKDIR /build
COPY challenge/vault.c ./vault.c
COPY setup/ ./setup/

# Genere secret.h + flags, compile, installe dans /challenge.
RUN LICENSE="$LICENSE" FLAG1="$FLAG1" FLAG2="$FLAG2" XOR_KEY="$XOR_KEY" \
        python3 setup/gen_secret.py && \
    gcc -fno-stack-protector -no-pie -fno-pie -O0 -w -o vault vault.c && \
    mkdir -p /challenge && \
    cp vault /challenge/vault && \
    cp flag1.txt flag2.txt /challenge/ && \
    chmod 0555 /challenge/vault && \
    chmod 0444 /challenge/flag1.txt /challenge/flag2.txt && \
    rm -rf /build

COPY docker-entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

WORKDIR /challenge
EXPOSE 9003
USER ctf
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# ── Dépendances applicatives ─────────────────────────────────────────────────
WORKDIR /opt/app
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Code de l'application ────────────────────────────────────────────────────
COPY app/ /opt/app/

# ── Utilisateur non-root (bonne pratique, l'appli n'a besoin d'aucun privilège) ─
RUN useradd --system --no-create-home ctfapp \
    && chown -R ctfapp:ctfapp /opt/app
USER ctfapp

# ── Secrets du challenge : surchargeables au run, valeurs faibles par défaut ──
# (le challenge FONCTIONNE tel quel ; on peut durcir/varier via -e si besoin)
ENV JWT_SECRET=spring2024
ENV AES_KEY=nexuslegacykey01
ENV VAULT_KEY=v4ultAEScbckey!!
ENV VAULT_IV=1234567890abcdef
ENV LENEXT_SECRET=n3xusS3cr3t42

# ── Port applicatif (à déclarer dans le champ "port" du challenge CTFd) ───────
EXPOSE 8080

# ── Lancement via gunicorn (multi-requêtes, robuste pour un CTF) ──────────────
CMD ["python", "-m", "gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "app:app"]

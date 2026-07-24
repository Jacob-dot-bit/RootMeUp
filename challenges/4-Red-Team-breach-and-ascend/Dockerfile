# Breach & Ascend — Helios Staff Portal
# Étape actuelle : portail web + upload contournable uniquement.
# (Pas encore de flags ni de partie privesc.)

FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    APACHE_RUN_USER=www-data \
    APACHE_RUN_GROUP=www-data

# Apache + PHP (module Apache) + outils système du scénario (sudo, tar).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        apache2 \
        libapache2-mod-php \
        sudo \
        tar \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Configuration Apache : AllowOverride All EN DUR sur le docroot,
# pour que le .htaccess de uploads/ (exécution des .phtml/.php5/.phar)
# soit bien pris en compte. Le listing reste désactivé par défaut.
RUN printf '%s\n' \
    '<Directory /var/www/html>' \
    '    Options -Indexes +FollowSymLinks' \
    '    AllowOverride All' \
    '    Require all granted' \
    '</Directory>' \
    > /etc/apache2/conf-available/helios.conf \
    && a2enconf helios >/dev/null

# Dépôt du portail dans le docroot.
COPY web/ /var/www/html/

# Le dossier de dépôt doit être inscriptible par Apache (www-data),
# sans recourir à un chmod 777 : www-data comme propriétaire suffit.
RUN chown -R root:root /var/www/html \
    && chown -R www-data:www-data /var/www/html/uploads \
    && chmod 755 /var/www/html/uploads

# --- Chaîne d'exploitation (vulnérabilités INTENTIONNELLES) ---------------
# Utilisateur employé "j.martin". Son mot de passe système est IDENTIQUE
# au mot de passe présent en clair dans web/config.php (réutilisation de
# mot de passe = vecteur du flag 2).
RUN useradd --create-home --shell /bin/bash j.martin \
    && echo 'j.martin:Helios#Pr0d_2024!' | chpasswd

# Entrée sudo NOPASSWD sur /usr/bin/tar pour j.martin
# (privesc GTFOBins via tar --checkpoint-action = vecteur du flag 3).
# NB : le nom du fichier ne doit PAS contenir de point — sudo ignore
# tout fichier de sudoers.d/ dont le nom contient un '.' ou finit par '~'.
RUN echo 'j.martin ALL=(root) NOPASSWD: /usr/bin/tar' \
        > /etc/sudoers.d/jmartin \
    && chmod 440 /etc/sudoers.d/jmartin \
    && visudo -cf /etc/sudoers.d/jmartin

# --- Placement des flags (paramétrables au build via --build-arg) ---------
# Valeurs par défaut = placeholders, à régénérer au build sans toucher au code :
#   docker build --build-arg FLAG1=FLAG{...} --build-arg FLAG2=... ...
ARG FLAG1=FLAG{placeholder_foothold_www_data}
ARG FLAG2=FLAG{placeholder_user_jmartin}
ARG FLAG3=FLAG{placeholder_root_privesc}

# FLAG 1 — foothold www-data.
# HORS du docroot (/var/www/html) : Apache ne le sert donc PAS en HTTP.
# Lisible par www-data uniquement via exécution de commande (RCE).
RUN printf '%s\n' "$FLAG1" > /var/www/flag1.txt \
    && chown www-data:www-data /var/www/flag1.txt \
    && chmod 640 /var/www/flag1.txt

# FLAG 2 — compte j.martin. Propriétaire j.martin, 600 : www-data ne peut pas lire.
RUN printf '%s\n' "$FLAG2" > /home/j.martin/user.txt \
    && chown j.martin:j.martin /home/j.martin/user.txt \
    && chmod 600 /home/j.martin/user.txt

# FLAG 3 — root. Propriétaire root, 600 : lisible seulement après privesc.
RUN printf '%s\n' "$FLAG3" > /root/root.txt \
    && chown root:root /root/root.txt \
    && chmod 600 /root/root.txt

EXPOSE 80

CMD ["apache2ctl", "-D", "FOREGROUND"]

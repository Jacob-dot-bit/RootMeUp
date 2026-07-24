# Breach & Ascend — Helios Staff Portal
# Étape actuelle : portail web + upload contournable uniquement.
# (Pas encore de flags ni de partie privesc.)

FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    APACHE_RUN_USER=www-data \
    APACHE_RUN_GROUP=www-data

# Apache + PHP (module Apache).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        apache2 \
        libapache2-mod-php \
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

EXPOSE 80

CMD ["apache2ctl", "-D", "FOREGROUND"]

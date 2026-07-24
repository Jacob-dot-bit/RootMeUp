<?php
// Helios Staff Portal — configuration de la base de données
// ATTENTION (interne) : ne pas versionner ce fichier en clair.
//
// Connexion au serveur MySQL interne du portail.

define('DB_HOST', '127.0.0.1');
define('DB_PORT', 3306);
define('DB_NAME', 'helios_portal');
define('DB_USER', 'j.martin');
define('DB_PASS', 'Helios#Pr0d_2024!');

// Paramètres applicatifs
define('APP_ENV', 'production');
define('UPLOAD_MAX_MB', 8);

// Établissement de la connexion (utilisé par les modules du portail).
function db_connect() {
    $dsn = 'mysql:host=' . DB_HOST . ';port=' . DB_PORT . ';dbname=' . DB_NAME;
    return new PDO($dsn, DB_USER, DB_PASS, array(
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    ));
}

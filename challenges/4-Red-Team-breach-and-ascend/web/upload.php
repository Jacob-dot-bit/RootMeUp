<?php
// Helios Staff Portal — dépôt de rapports
// Le service RH n'accepte que des images ou des PDF numérisés.

$uploadDir = __DIR__ . '/uploads/';
$message = null;
$messageType = null;

// Types MIME "autorisés" (contrôle basé sur le Content-Type déclaré par le client).
$allowedMime = array(
    'image/jpeg',
    'image/png',
    'image/gif',
    'application/pdf',
);

// Extensions explicitement refusées pour éviter le dépôt de scripts.
$blockedExt = array('php', 'php3', 'php4', 'phtm', 'htaccess');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_FILES['report']) || $_FILES['report']['error'] !== UPLOAD_ERR_OK) {
        $message = "Aucun fichier valide n'a été reçu. Veuillez réessayer.";
        $messageType = 'error';
    } else {
        $file = $_FILES['report'];
        $name = basename($file['name']);
        $ext  = strtolower(pathinfo($name, PATHINFO_EXTENSION));

        // 1) Contrôle du type MIME déclaré par le navigateur.
        if (!in_array($file['type'], $allowedMime, true)) {
            $message = "Type de fichier non autorisé (" . htmlspecialchars($file['type']) . "). "
                     . "Seuls les fichiers image ou PDF sont acceptés.";
            $messageType = 'error';
        }
        // 2) Contrôle de l'extension via une liste noire.
        elseif (in_array($ext, $blockedExt, true)) {
            $message = "Extension de fichier interdite (." . htmlspecialchars($ext) . ").";
            $messageType = 'error';
        }
        else {
            if (!is_dir($uploadDir)) {
                mkdir($uploadDir, 0755, true);
            }
            $target = $uploadDir . $name;
            if (move_uploaded_file($file['tmp_name'], $target)) {
                $message = "Rapport « " . htmlspecialchars($name) . " » déposé avec succès. "
                         . "Il est consultable dans l'espace de dépôt.";
                $messageType = 'success';
            } else {
                $message = "Erreur interne lors de l'enregistrement du fichier.";
                $messageType = 'error';
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Déposer un rapport — Helios Staff Portal</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
<header class="topbar">
    <div class="brand">
        <span class="logo">☀</span>
        <span class="brand-name">Helios Corp</span>
        <span class="brand-sub">Staff Portal</span>
    </div>
    <nav class="topnav">
        <a href="index.php">Accueil</a>
        <a href="upload.php" class="active">Déposer un rapport</a>
        <a href="#" onclick="return false;">Annuaire</a>
        <a href="#" onclick="return false;">Déconnexion</a>
    </nav>
</header>

<main class="container">
    <section class="hero">
        <h1>Déposer un rapport</h1>
        <p class="lead">
            Sélectionnez un document à transmettre au service RH. Formats
            acceptés : images (JPEG, PNG, GIF) et PDF. Taille maximale : 8 Mo.
        </p>
    </section>

    <?php if ($message !== null): ?>
        <div class="alert alert-<?php echo $messageType; ?>">
            <?php echo $message; ?>
        </div>
    <?php endif; ?>

    <section class="card form-card">
        <form action="upload.php" method="post" enctype="multipart/form-data">
            <label for="report">Document à déposer</label>
            <input type="file" name="report" id="report" required>
            <p class="muted">
                Vos documents restent confidentiels et ne sont accessibles
                qu'au service administratif.
            </p>
            <button type="submit" class="btn">Envoyer le rapport</button>
        </form>
    </section>
</main>

<footer class="footer">
    <p>© <?php echo date('Y'); ?> Helios Corp — Usage strictement interne. Toute connexion est journalisée.</p>
</footer>
</body>
</html>

<?php
// Helios Staff Portal — page d'accueil interne
$year = date('Y');
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Helios Staff Portal — Espace interne</title>
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
        <a href="index.php" class="active">Accueil</a>
        <a href="upload.php">Déposer un rapport</a>
        <a href="#" onclick="return false;">Annuaire</a>
        <a href="#" onclick="return false;">Déconnexion</a>
    </nav>
</header>

<main class="container">
    <section class="hero">
        <h1>Bienvenue sur le portail interne Helios</h1>
        <p class="lead">
            Cet espace est réservé aux collaborateurs de Helios Corp. Vous pouvez
            y déposer vos rapports d'activité, notes de frais numérisées et
            documents de synthèse à destination du service administratif.
        </p>
    </section>

    <section class="cards">
        <article class="card">
            <h2>📄 Déposer un rapport</h2>
            <p>
                Transmettez vos documents (images ou PDF) au service RH. Les
                fichiers sont conservés dans l'espace de dépôt sécurisé.
            </p>
            <a class="btn" href="upload.php">Accéder au dépôt</a>
        </article>

        <article class="card">
            <h2>📢 Annonces</h2>
            <ul class="news">
                <li><strong>18/07</strong> — Migration du portail vers la nouvelle infrastructure interne.</li>
                <li><strong>12/07</strong> — Rappel : merci de déposer vos rapports mensuels avant le 5 du mois.</li>
                <li><strong>03/07</strong> — Maintenance planifiée du serveur de fichiers ce week-end.</li>
            </ul>
        </article>

        <article class="card">
            <h2>🛟 Support</h2>
            <p>
                Un problème avec le portail ? Contactez l'équipe informatique à
                <a href="mailto:it-support@helios.corp">it-support@helios.corp</a>.
            </p>
            <p class="muted">Support interne — poste 4021</p>
        </article>
    </section>
</main>

<footer class="footer">
    <p>© <?php echo $year; ?> Helios Corp — Usage strictement interne. Toute connexion est journalisée.</p>
</footer>
</body>
</html>

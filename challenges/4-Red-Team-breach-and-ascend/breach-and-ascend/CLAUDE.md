# Challenge "Breach & Ascend"

## Scénario
Helios Corp, PME fictive. Portail interne "Helios Staff Portal" permettant
aux employés de déposer des rapports. Box Linux vulnérable, exploitable en
3 étapes progressives (3 flags) : accès web -> compte employé -> root.

## RÈGLE ABSOLUE : vulnérabilités INTENTIONNELLES
Les failles ci-dessous DOIVENT rester exploitables, ne jamais les corriger :
- filtre d'upload contournable (Content-Type + blacklist d'extensions,
  oublie .phtml/.php5/.phar)
- exécution des .phtml dans le dossier uploads/
- mot de passe en clair dans config.php, réutilisé comme mot de passe système
- entrée sudo NOPASSWD sur /usr/bin/tar pour l'utilisateur j.martin

## Chaîne d'exploitation prévue
1. Foothold : bypass upload -> web shell .phtml -> RCE www-data -> FLAG 1
2. Lateral : lire config.php -> mot de passe réutilisé -> su j.martin -> FLAG 2
3. Privesc : sudo tar (GTFOBins --checkpoint-action) -> root -> FLAG 3

## Placement des flags (CRITIQUE)
- flag1.txt HORS docroot (/var/www/flag1.txt), lisible par www-data via RCE only
- user.txt chmod 600 owner j.martin (/home/j.martin/user.txt)
- root.txt chmod 600 owner root (/root/root.txt)

## Contraintes techniques
- Base : Debian + Apache + PHP + sudo. Un seul port exposé (web).
- Documenter la solution attendue dans SOLUTION.md au fur et à mesure.

# Rapport de durcissement — srv-legacy01 (Operation IRON GATE)

- **Administrateur :** _______________________
- **Équipe :** _______________________
- **Date :** _______________________

## 1. Résumé
_(État initial du serveur, niveau de risque, temps de remédiation)_

## 2. Vulnérabilités corrigées (difficulté croissante)
| # | Palier | Faille | Correctif appliqué | Flag | Réf. CIS / MITRE |
|---|--------|--------|--------------------|------|------------------|
| 1 | facile | SSH root login autorisé | | NW{...} | CIS 5.2.x |
| 2 | facile | Mots de passe SSH vides | | | CIS 5.2.x |
| 3 | facile | /etc/shadow world-readable | | | CIS 6.1.x |
| 4 | moyen | Secret applicatif en clair | | | T1552.001 |
| 5 | moyen | Cron de persistance (C2) | | | T1053.003 |
| 6 | moyen | Service telnet actif | | | T1021 |
| 7 | difficile | Compte caché UID 0 | | | T1136 |
| 8 | difficile | Binaire SUID root | | | T1548.001 |
| 9 | expert | Répertoire du PATH world-writable | | | T1574.007 |
| 10 | expert | Clé SSH backdoor (root) | | | T1098.004 |

## 3. Vérification finale
```
audit  ->  __ / 10 correctifs validés
```

## 4. Recommandations complémentaires
_(Au-delà des 10 points : MàJ système, fail2ban, journalisation centralisée,
pare-feu, MFA, principe du moindre privilège, sauvegardes, etc.)_

## 5. Enseignements
_(Ce que le durcissement proactif apporte vs l'analyse post-incident)_

# Operation SILENT LEDGER — Brief joueur

> Ceci est le texte destiné à être copié/collé dans CTFd (description de catégorie /
> de challenge). Le ton est volontairement "rapport de mission red team".

## Briefing

**Client :** Meridian Capital (société fictive de gestion d'actifs)
**Mandat :** Red Team engagement — post-exploitation
**Contexte :** La phase de reconnaissance et d'ingénierie sociale a déjà été menée par
une autre équipe. Une campagne de phishing a permis d'obtenir les identifiants SSH
d'un stagiaire IT, `j.martin`. Vous prenez le relais à partir de cet accès initial.

**Objectif :** Élever vos privilèges pas à pas jusqu'à l'exfiltration complète des
données sensibles de Meridian Capital. Le chemin comporte **10 étapes (flags)**,
de la simple reconnaissance jusqu'à la compromission totale. Chaque étape rapporte
des points croissants — soumettez-les au fur et à mesure dans CTFd, vous n'avez
pas besoin d'attendre la fin pour scorer.

**Règles :**
- Une seule instance Docker à lancer (bouton "Start Instance"). Tout le challenge
  se déroule dessus, du flag 1 au flag 10.
- Accès initial : `ssh j.martin@<host> -p <port>` — mot de passe fourni ci-dessous.
- Ne détruisez pas volontairement l'instance des autres participants, ni la vôtre
  avant d'avoir fini (le bouton "Stop"/"Restart" vous redonne un environnement propre
  mais réinitialise votre progression sur la machine).
- Interdiction de bruteforcer le port SSH exposé ou de scanner l'infrastructure CTFd —
  tout est fourni pas à pas via l'énumération normale.

**Identifiants de départ :**
```
user: j.martin
pass: Welcome2024!
```

## Barème

| # | Titre du challenge                          | Technique                                            | Points |
|---|----------------------------------------------|-------------------------------------------------------|-------:|
| 1 | Premiers pas                                  | Reconnaissance / lecture de fichiers                  |     50 |
| 2 | Fouille de printemps                          | Énumération du système de fichiers                    |     75 |
| 3 | Mauvaise mémoire                              | Récolte d'identifiants (historique shell)             |    100 |
| 4 | Tâche planifiée                               | Privesc via cron job inscriptible                     |    125 |
| 5 | Journaux confidentiels                        | Binaire SUID vulnérable (injection de commande)       |    150 |
| 6 | Délégation hasardeuse                         | Mauvaise configuration sudo (GTFOBins)                 |    175 |
| 7 | Pouvoirs spéciaux                             | Abus de capabilities Linux                             |    200 |
| 8 | L'orchestrateur                               | Désérialisation non sécurisée (RCE root)              |    225 |
| 9 | Le coffre                                     | Cassage de mot de passe hors-ligne (zip)               |    250 |
| 10| Silent Ledger                                 | Cassage de PIN + déchiffrement GPG (final)             |    300 |

**Total : 1650 points**

## Description à coller par challenge (CTFd)

### 1 — Premiers pas (50 pts)
> Vous venez d'obtenir un accès SSH via une campagne de phishing réussie sur un
> stagiaire IT. Connectez-vous et commencez votre reconnaissance. Que laissent
> traîner les nouveaux employés dans leur répertoire personnel ?
>
> `ssh j.martin@<host> -p <port>` — mot de passe : `Welcome2024!`
>
> Format du flag : `MERIDIAN{...}`

### 2 — Fouille de printemps (75 pts)
> Les sauvegardes système sont rarement bien nettoyées. Un peu de méthode
> (`find`, `grep -r`) devrait payer.

### 3 — Mauvaise mémoire (100 pts)
> Tout le monde fait des erreurs de frappe un jour ou l'autre — y compris en tapant
> un mot de passe au mauvais endroit. Les habitudes ne s'effacent pas si facilement.

### 4 — Tâche planifiée (125 pts)
> Un compte de service tourne toutes les nuits (enfin, toutes les minutes ici, pour
> ne pas vous faire attendre). Qui exécute quoi, et avec quelles permissions ?

### 5 — Journaux confidentiels (150 pts)
> L'équipe IT a développé un petit outil interne pour consulter les logs sans
> donner un accès root complet aux analystes. Est-il aussi sûr qu'il en a l'air ?

### 6 — Délégation hasardeuse (175 pts)
> Un analyste dispose de quelques privilèges `sudo` très ciblés. Trop ciblés,
> peut-être pas assez.

### 7 — Pouvoirs spéciaux (200 pts)
> Root n'est pas le seul moyen de contourner les permissions du système de
> fichiers sous Linux.

### 8 — L'orchestrateur (225 pts)
> Meridian gère sa flotte de serveurs avec un outil interne maison. Les outils
> maison ont parfois des défauts que les outils du commerce n'ont plus depuis
> longtemps.

### 9 — Le coffre (250 pts)
> Certains secrets sont encore chiffrés. Un mot de passe faible ne résiste jamais
> bien longtemps à un dictionnaire.

### 10 — Silent Ledger (300 pts)
> Dernière ligne droite. Une dernière couche de chiffrement protège les données
> les plus sensibles de Meridian Capital. Prouvez que vous êtes allé jusqu'au bout
> de l'engagement.

## Note sur les indices (hints CTFd)

Pour un public de M2, je recommande de **ne pas** activer d'indices payants sur les
challenges 1 à 4 (trop simple), mais d'en prévoir un discret (coût 10-15% des points)
sur 5, 6, 7, 8 et 9, du type :

- F5 : "Cherchez les binaires SUID sur le système, puis étudiez ce qu'ils exécutent
  en interne (`strings`, `ltrace`)."
- F6 : "`sudo -l` est votre ami. GTFOBins aussi."
- F7 : "`getcap -r / 2>/dev/null` révèle des choses intéressantes."
- F8 : "Le protocole de l'orchestrateur accepte un token. Un des fichiers déjà
  récupérés en contient un."
- F9 : "`zip2john` + une wordlist connue suffisent."
- F10 : "`hashcat` avec une attaque par masque sur 6 chiffres est quasi instantané."

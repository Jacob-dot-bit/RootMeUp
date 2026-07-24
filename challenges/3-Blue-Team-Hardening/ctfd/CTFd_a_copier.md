# CTFd — Contenu prêt à copier (Operation IRON GATE)

Catégorie : **Blue Team - Durcissement srv-legacy01**
Format des flags : `NW{...}` (statique, sensible à la casse)

> Rappel montage : **Flag 1** = challenge de type *container* (bouton *Start
> Instance*, image `nw-hardening:latest`, port `8000`). **Flags 2 → 10** = type
> *standard*, chacun avec en **Prérequis** la question précédente (déblocage
> progressif). Les flags sont validés par le service grader ; le joueur les
> obtient avec `getflag <N>` dans le terminal.

---

## Flag 1 — Instance et Flag 1 : Verrouiller l'accès SSH root
**Points : 50** · Type : *container* (image `nw-hardening:latest`, port 8000)

**Description :**

**Durcissement système — Operation IRON GATE**

NORTHWIND Trading Co. vient de récupérer un vieux serveur, **srv-legacy01**,
hérité d'un prestataire parti sans documentation. L'audit initial est alarmant :
connexion root SSH autorisée, compte caché, tâche planifiée suspecte, secrets en
clair, service obsolète encore actif… Un attaquant qui tomberait dessus en ferait
une bouchée.

Vous êtes le **nouvel administrateur Blue Team**. Votre mission n'est pas
d'analyser une attaque passée, mais d'**empêcher la prochaine** : durcir le
serveur, faille après faille, avant qu'il ne soit trop tard. 10 corrections à
**difficulté croissante**, de la configuration SSH la plus basique jusqu'aux
backdoors les plus discrètes.

**Comment accéder au challenge**
- Cliquez sur **Start Instance** pour démarrer votre instance dédiée. Elle est
  attribuée à votre équipe : tous les membres partagent la même, inutile d'en
  lancer plusieurs.
- Vous recevrez une adresse `http://<hôte>:<port>` qui ouvre un **terminal web**
  sur srv-legacy01 (session `analyst`, `sudo` disponible). **Une seule et même
  instance sert du premier au dernier flag. Ne la détruisez pas entre deux flags.**
- Tapez **`audit`** pour voir votre progression (ce qui reste à corriger, niveau
  par niveau). Corrigez une faille avec `sudo …`, puis tapez **`getflag <N>`**
  (ex. `getflag 1`) pour récupérer le flag de cette étape et le **soumettre ici**.
- Pensez à prolonger l'instance (*Add Time*) si elle approche de l'expiration.

**Flags :** 10 flags à difficulté croissante qui suivent le durcissement du
serveur. Les premiers sont de la configuration directe ; les derniers demandent
de repérer des backdoors subtiles, **sans indice**. Format : `NW{...}`.

**Flag 1 —** La configuration SSH héritée autorise la connexion directe du compte
**root** : une porte grande ouverte sur toute la machine. Interdisez cette
connexion dans la configuration du service SSH, puis récupérez votre flag avec
`getflag 1`.

**Flag :** `NW{r00t_l0gin_disabled}`

---

## Flag 2 — Mots de passe vides
**Points : 50** · Type : *standard* · Prérequis : Flag 1

**Description :**
Toujours côté SSH : le service accepte encore les comptes dont le **mot de passe
est vide** — une authentification qui n'en est pas une. Coupez définitivement
cette possibilité dans la configuration du service. (`getflag 2`)

**Flag :** `NW{n0_empty_passw0rds}`

---

## Flag 3 — Le fichier des empreintes
**Points : 75** · Type : *standard* · Prérequis : Flag 2

**Description :**
Le fichier système qui contient les **empreintes des mots de passe** de tous les
comptes est actuellement lisible par n'importe quel utilisateur de la machine —
de quoi tenter un cassage hors ligne. Rétablissez des permissions correctes.
(`getflag 3`)

**Flag :** `NW{shadow_l0cked_down}`

---

## Flag 4 — Secrets applicatifs exposés
**Points : 100** · Type : *standard* · Prérequis : Flag 3

**Description :**
Une application laisse traîner ses **secrets** (identifiants de base de données,
clés) dans un fichier de configuration lisible par tout le monde. Restreignez-en
l'accès pour que seul son propriétaire puisse le lire. (`getflag 4`)

**Flag :** `NW{secrets_perms_600}`

---

## Flag 5 — Persistance planifiée
**Points : 100** · Type : *standard* · Prérequis : Flag 4

**Description :**
Une **tâche planifiée** s'exécute toutes les cinq minutes et contacte un serveur
externe : ce n'est pas une mise à jour, c'est une **balise** laissée par
l'attaquant. Faites-la disparaître. (`getflag 5`)

**Flag :** `NW{malicious_cron_purged}`

---

## Flag 6 — Service en clair
**Points : 125** · Type : *standard* · Prérequis : Flag 5

**Description :**
Un **service d'administration à distance en clair**, d'un autre âge, écoute
encore sur la machine — tout mot de passe qui y transiterait serait lisible sur
le réseau. Désactivez-le. (`getflag 6`)

**Flag :** `NW{telnet_is_dead}`

---

## Flag 7 — Compte administrateur caché
**Points : 150** · Type : *standard* · Prérequis : Flag 6

**Description :**
L'attaquant a laissé de quoi revenir : un **compte discret possède les mêmes
privilèges que root**. Repérez-le et supprimez-le.
*Indice méthodo : tous les comptes tout-puissants ne s'appellent pas « root ».*
(`getflag 7`)

**Flag :** `NW{no_hidden_r00t_user}`

---

## Flag 8 — Binaire SUID
**Points : 175** · Type : *standard* · Prérequis : Flag 7

**Description :**
Un **binaire du système peut être exécuté avec les privilèges de root** par
n'importe quel utilisateur : une élévation de privilèges toute prête pour un
attaquant. Neutralisez-la sans casser le binaire. (`getflag 8`)

**Flag :** `NW{suid_backdoor_cleared}`

---

## Flag 9 — Intégrité du PATH
**Points : 225** · Type : *standard* · Prérequis : Flag 8

**Description :**
**Aucun indice.** La commande `audit` signale un problème d'**intégrité du
PATH**. Quelque part, un répertoire du chemin d'exécution est modifiable par
n'importe qui : un attaquant pourrait y déposer un binaire malveillant qui serait
exécuté à la place d'un programme légitime. Trouvez la faille et corrigez-la.
(`getflag 9`)

**Flag :** `NW{writable_path_secured}`

---

## Flag 10 — Accès distant résiduel
**Points : 250** · Type : *standard* · Prérequis : Flag 9

**Description :**
**Aucun indice.** Même après tout ce travail, l'attaquant peut encore revenir :
un **accès distant résiduel** subsiste quelque part sur le compte root. Trouvez-le
et éliminez-le pour boucler définitivement le durcissement de srv-legacy01.
(`getflag 10`)

**Flag :** `NW{ssh_backdoor_key_removed}`

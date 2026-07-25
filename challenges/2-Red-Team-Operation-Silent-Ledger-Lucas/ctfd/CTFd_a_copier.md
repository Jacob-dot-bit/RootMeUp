# CTFd — Contenu prêt à copier (Operation SILENT LEDGER)

Catégorie : **Red Team — Silent Ledger**
Format des flags : `RootMeUp{...}` (statique, sensible à la casse)

> Montage : **Flag 1** = challenge type *container* (bouton *Start Instance*,
> image `rootmeup/rt2-silent-ledger:1.0`, port **22/tcp**). **Flags 2 → 10** =
> type *standard*, chacun avec en **Requirements** la question précédente
> (chaîne linéaire F1→…→F10). Le joueur reste sur la même instance du 1er au
> dernier flag.
>
> ⚠️ L'instance DOIT être lancée avec `--cap-add DAC_READ_SEARCH` (flag 7).
> Voir `docs/CTFD_SETUP.md`.

---

## Flag 1 — Premiers pas (50 pts) — challenge CONTENEUR
**Type : container · Image : `rootmeup/rt2-silent-ledger:1.0` · Port : 22**

**Description :**

**Meridian Capital — Red Team engagement (post-exploitation)**

La reconnaissance et l'ingénierie sociale ont déjà été menées : une campagne de
phishing a fourni les identifiants SSH d'un stagiaire IT, `j.martin`. Vous prenez
le relais à partir de cet accès initial et devez élever vos privilèges, étape par
étape, jusqu'à l'exfiltration complète des données sensibles de Meridian.

**10 étapes (flags)**, de la simple reconnaissance à la compromission totale.
Soumettez chaque flag au fur et à mesure — pas besoin d'attendre la fin.

**Accès :** cliquez sur **Start Instance**. Vous obtenez une adresse
`ssh j.martin@<hôte> -p <port>` (mot de passe : `Welcome2024!`). Une seule
instance par équipe, du premier au dernier flag — ne la détruisez pas entre deux
flags. Format des flags : `RootMeUp{...}`.

**Flag 1 —** Connectez-vous et commencez votre reconnaissance. Que laissent
traîner les nouveaux employés dans leur répertoire personnel ?

**Flag :** `RootMeUp{f1rst_st3ps_1nt0_th3_n3tw0rk_3a1c9d}`

---

## Flag 2 — Fouille de printemps (75 pts) — standard · Prérequis : F1
Les sauvegardes système sont rarement bien nettoyées. Un peu de méthode
(`find`, `grep -r`) devrait payer.

**Flag :** `RootMeUp{h1dd3n_1n_pla1n_s1ght_7b2e41}`

---

## Flag 3 — Mauvaise mémoire (100 pts) — standard · Prérequis : F2
Tout le monde fait des erreurs de frappe — y compris en tapant un mot de passe au
mauvais endroit. Les habitudes shell ne s'effacent pas si facilement.

**Flag :** `RootMeUp{h1st0ry_r3p3ats_1ts3lf_c48a02}`

---

## Flag 4 — Tâche planifiée (125 pts) — standard · Prérequis : F3
Un job tourne toutes les minutes. Regardez **sous quelle identité** il s'exécute
et **qui** peut modifier ce qu'il lance.

**Flag :** `RootMeUp{cr0n_j0bs_ar3_g0ld_9d17f3}`

---

## Flag 5 — Délégation hasardeuse (150 pts) — standard · Prérequis : F4
Ce compte dispose de quelques privilèges `sudo` très ciblés. Trop ciblés, ou pas
assez ? (`sudo -l`, puis GTFOBins.)

**Flag :** `RootMeUp{sud0_m1sc0nf1g_str1k3s_ag41n_e0a934}`

---

## Flag 6 — Journaux confidentiels (175 pts) — standard · Prérequis : F5
L'équipe IT a écrit un petit outil interne pour consulter les logs sans donner
un accès complet. Est-il aussi sûr qu'il en a l'air ? (Cherchez les binaires
SUID, puis étudiez ce qu'ils exécutent.)

**Flag :** `RootMeUp{su1d_b1nar13s_l13_0ft3n_2f6b58}`

---

## Flag 7 — Pouvoirs spéciaux (200 pts) — standard · Prérequis : F6
Root n'est pas le seul moyen de contourner les permissions de fichiers sous
Linux. (`getcap -r / 2>/dev/null`.)

**Flag :** `RootMeUp{cap4bilit13s_ar3_p0w3r_5c2d71}`

---

## Flag 8 — L'orchestrateur (225 pts) — standard · Prérequis : F7
Meridian gère sa flotte avec un outil maison. Les outils maison ont parfois des
défauts que les outils du commerce n'ont plus depuis longtemps. (Le protocole
accepte un token — vous venez de le récupérer.)

**Flag :** `RootMeUp{0rch3str4t0r_pwn3d_88af0d}`

---

## Flag 9 — Le coffre (250 pts) — standard · Prérequis : F8
Certains secrets sont encore chiffrés. Un mot de passe faible ne résiste jamais
bien longtemps à un dictionnaire. (`zip2john` + rockyou.)

**Flag :** `RootMeUp{cr4ck3d_th3_v4ult_1e39b6}`

---

## Flag 10 — Silent Ledger (300 pts) — standard · Prérequis : F9
Dernière ligne droite. Une dernière couche de chiffrement protège les données les
plus sensibles. (`hashcat` masque 6 chiffres, puis GPG.)

**Flag :** `RootMeUp{0p3ration_s1l3nt_l3dg3r_c0mpl3t3_f4a217}`

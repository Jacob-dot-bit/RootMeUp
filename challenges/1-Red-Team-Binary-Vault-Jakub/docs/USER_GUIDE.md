# 🔴 VAULT-9 — Guide du joueur

**Catégorie :** Red Team — Reverse & Exploitation binaire
**Difficulté :** Intermédiaire
**Flags :** 2 (progressifs)

## 📖 Contexte

L'entreprise **Meridian Corp** protège son module mémoire sensible derrière une console d'administration maison, `VAULT-9`. Un binaire de cette console a fuité. Votre équipe doit démontrer qu'il est vulnérable : contourner sa licence, puis en prendre le contrôle pour ouvrir le coffre.

## 🎯 Objectifs

1. **Flag 1** — Contourner la vérification de licence du binaire.
2. **Flag 2** — Prendre le contrôle de l'exécution pour atteindre la routine qui ouvre le coffre.

Format des flags : `RM{...}` (sensible à la casse).

## 🔌 Accès

1. Téléchargez le binaire **`vault`** fourni avec le challenge dans CTFd.
2. Démarrez l'instance (**Start Instance**) : vous obtenez une **IP** et un **port**.
3. Connectez-vous au service :

   ```bash
   nc <ip> <port>
   ```

Le binaire téléchargé est **identique** à celui qui tourne sur l'instance : analysez-le en local, exploitez-le à distance.

## 🧰 Outils suggérés

- **Reverse** : `Ghidra`, `IDA Free`, `radare2`/`Cutter`, ou simplement `objdump -d vault`.
- **Exploitation** : `pwntools` (Python), `gdb` + `pwndbg`/`gef`.
- **Recon** : `file vault`, `checksec vault`, `strings vault`.

## 🪜 Pistes (sans spoiler)

- Étape 1 : commencez par `file` et `checksec`. Cherchez la fonction qui valide la licence. Quelle **opération** est appliquée à votre saisie avant la comparaison ? La donnée de référence est en clair dans le binaire… mais transformée.
- Étape 2 : une fois « administrateur », le terminal de maintenance lit votre entrée. Combien d'octets accepte-t-il vraiment vs la taille du tampon ? Existe-t-il une fonction **intéressante jamais appelée** ?

## ✅ Validation

Soumettez chaque flag dans CTFd. Le flag 1 se trouve dès l'accès administrateur ; le flag 2 nécessite de détourner l'exécution.

Bon courage — et n'oubliez pas : *ne codez jamais un secret en dur.* 😉

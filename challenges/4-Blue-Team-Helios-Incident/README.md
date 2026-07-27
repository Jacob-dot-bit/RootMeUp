# 🔵 Blue Team 4 — Helios Incident

**Auteur :** Evan
**Forensic réseau** : analyser une capture (`.pcap`) prise pendant la compromission du
serveur web interne d'Helios Corp, et **reconstituer la chaîne d'attaque**.

> ⚠️ **Challenge en cours de finalisation** — pour l'instant le dossier ne contient que
> `capture.pcap`. Reste à faire (Evan) : définir les **flags/questions**, choisir le
> **mode de livraison** (PCAP en pièce jointe vs boîte instanciée), et ajouter la solution.

## 🎯 Résumé

| | |
|---|---|
| Catégorie | Blue Team — Forensic réseau (analyse de capture) |
| Difficulté | Intermédiaire |
| Flags | série progressive — **format à définir** (`RootMeUp{...}` recommandé pour rester cohérent) |
| Accès joueur | **Téléchargement** de `capture.pcap` (pas d'instance) — analyse locale (Wireshark/tshark/Zeek) |
| Image / Port | _N/A (fichier PCAP)_ |

## 📖 Scénario (reconstitué depuis la capture)

Le serveur web interne (`192.168.10.20`) d'Helios Corp a été compromis. La capture montre
une chaîne d'attaque complète :

1. **Intrusion web** — dépôt d'un fichier via la fonction d'upload de l'application, puis
   **exécution de commandes** à distance (webshell `.phtml`).
2. **Command & Control** — communication sortante vers un domaine externe (`helios-c2.xyz`).
3. **Exfiltration** — données sorties du réseau par **tunneling DNS** (sous-domaines encodés
   vers `exfil.helios-c2.xyz`).

## 🚩 Objectifs (flags) — proposition à valider

1. **Intrusion** — comment le code a été exécuté sur le serveur web (fichier déposé / requête).
2. **Prise de contrôle** — le webshell utilisé et sa clé d'accès.
3. **C2** — le domaine / l'IP de commande & contrôle.
4. **Exfiltration** — le domaine et la méthode (DNS), éventuellement la donnée exfiltrée décodée.

## 🗂️ Structure

```
capture.pcap            ← capture réseau à analyser (le cœur du challenge)
```

## 📚 Documentation

- Guide joueur (sans spoiler) : dépôt joueurs `RootMeUp-CTF` → `Blue-4-Helios-Incident`
- Solution / write-up : _à ajouter par Evan (`solution/SOLUTION.md`)._

> _TODO Evan : figer les flags + leur format, décider du mode de livraison, écrire la solution._

# 🔵 Blue Team – Rapport d'Analyse Mémoire

**Analyste :** _____________________  
**Date :** _____________________  
**Fichier analysé :** memory.dmp  

---

## 1. Résumé Exécutif

_Décrivez brièvement l'incident et vos conclusions principales._

---

## 2. Processus Malveillant Identifié

| Champ                | Valeur              |
|----------------------|---------------------|
| **PID**              |                     |
| **Nom du processus** |                     |
| **PID Parent (PPID)**|                     |
| **Chemin complet**   |                     |
| **Heure de création**|                     |

### Justification
_Expliquez pourquoi ce processus est suspect (nom, parentage, chemin, comportement)._

---

## 3. Analyse des Injections (malfind)

_Décrivez les sections mémoire suspectes trouvées :_

- **Adresse de base :**
- **Permissions :** (RWX ?)
- **Taille :**
- **Contenu notable :**

---

## 4. Extraction & Analyse du Binaire

_Résultats de l'extraction du processus / des fichiers :_

- **Hash MD5/SHA256 :**
- **Strings intéressantes :**
- **Comportement identifié :**

---

## 5. Communication C2

| Champ                | Valeur              |
|----------------------|---------------------|
| **IP/URL du C2**     |                     |
| **Port**             |                     |
| **Protocole**        |                     |
| **Fréquence beacon** |                     |

---

## 6. Flag Récupéré

```
FLAG : ___________________________
```

---

## 7. Corrélation Réseau (Bonus)

_Si un fichier PCAP était disponible, décrivez les connexions réseau confirmant l'exfiltration :_

- **IP source :**
- **IP destination :**
- **Données exfiltrées :**

---

## 8. Recommandations

1. _Isoler la machine compromise_
2. _Bloquer le C2 au niveau firewall_
3. _Scanner les autres machines du réseau_
4. _..._

---

## 9. Indicateurs de Compromission (IoC)

| Type      | Valeur                    | Description           |
|-----------|---------------------------|-----------------------|
| IP        |                           |                       |
| Domaine   |                           |                       |
| Hash      |                           |                       |
| Processus |                           |                       |

---

**Signature de l'analyste :** _____________________

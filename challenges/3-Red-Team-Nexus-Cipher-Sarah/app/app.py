#!/usr/bin/env python3
"""
RootMeUp - Red Team Challenge : "NEXUS Internal Portal"
Service web volontairement vulnerable. 10 flags a difficulte croissante,
chacun exploitant une faille cryptographique ou de logique applicative.

Chaque flag debloque conceptuellement l'etape suivante de la kill chain :
recon -> auth bypass -> role escalation -> data access -> secret recovery.

NOTE PEDAGOGIQUE (corrige) : les commentaires "# [FLAG n]" reperent
l'emplacement de chaque vulnerabilite dans le code.
"""

import base64
import hashlib
import hmac
import json
import os
import time
from flask import Flask, request, jsonify, make_response, render_template, redirect

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Secrets & config (charges depuis l'environnement, valeurs par defaut faibles
# VOLONTAIREMENT pour le challenge).
# ---------------------------------------------------------------------------
# [FLAG 3] Le secret HMAC est faible et crackable par bruteforce/wordlist.
JWT_SECRET = os.environ.get("JWT_SECRET", "spring2024")

# [FLAG 5] Cle AES-ECB (16 octets) pour le cookie de session "legacy".
AES_KEY = os.environ.get("AES_KEY", "nexuslegacykey01").encode()[:16]

# [FLAG 6] Cle AES-CBC pour le coffre de documents (padding oracle).
VAULT_KEY = os.environ.get("VAULT_KEY", "v4ultAEScbckey!!").encode()[:16]
VAULT_IV = os.environ.get("VAULT_IV", "1234567890abcdef").encode()[:16]

FLAGS = {
    1: "RootMeUp{r3c0n_h1dd3n_3ndp01nt}",
    2: "RootMeUp{jwt_4lg_n0n3_byp4ss}",
    3: "RootMeUp{w34k_hm4c_s3cr3t_cr4ck3d}",
    4: "RootMeUp{1d0r_h0r1z0nt4l_4cc3ss}",
    5: "RootMeUp{ecb_cut_4nd_p4st3_r0l3}",
    6: "RootMeUp{p4dd1ng_0r4cl3_d3crypt}",
    7: "RootMeUp{pr3d1ct4bl3_prng_r3s3t}",
    8: "RootMeUp{ss7i_j1nj4_s3rv3r_l34k}",
    9: "RootMeUp{h4sh_l3ngth_3xt3ns10n}",
    10: "RootMeUp{n3xus_r00t_d0m41n_pwn3d}",
}

# ---------------------------------------------------------------------------
# "Base de donnees" en memoire
# ---------------------------------------------------------------------------
USERS = {
    "guest":  {"id": 1000, "role": "guest",   "password": "guest",     "note": "Welcome guest."},
    "j.reyes": {"id": 1007, "role": "user",    "password": "Summer2024!", "note": FLAGS[4]},  # cible IDOR
    "admin":  {"id": 1,    "role": "admin",   "password": os.urandom(16).hex(), "note": "Admin console access."},
}

# Documents du coffre (flag 6 : un blob chiffre AES-CBC a dechiffrer)
def _aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, 16))

# ---------------------------------------------------------------------------
# Helpers JWT "maison" (volontairement faillible)
# ---------------------------------------------------------------------------
def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)

def jwt_encode(payload: dict, alg="HS256") -> str:
    header = {"alg": alg, "typ": "JWT"}
    h = b64url(json.dumps(header).encode())
    p = b64url(json.dumps(payload).encode())
    signing_input = f"{h}.{p}".encode()
    if alg == "none":
        return f"{h}.{p}."
    sig = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{b64url(sig)}"

def jwt_decode(token: str):
    """
    [FLAG 2] Accepte alg:none sans verification -> auth bypass.
    [FLAG 3] Verifie HS256 avec un secret faible -> crackable offline.
    """
    try:
        h_b64, p_b64, sig_b64 = token.split(".")
    except ValueError:
        return None
    header = json.loads(b64url_decode(h_b64))
    payload = json.loads(b64url_decode(p_b64))
    alg = header.get("alg", "").lower()

    if alg == "none":
        # VULN : aucune signature exigee
        return payload

    if alg == "hs256":
        expected = hmac.new(JWT_SECRET.encode(),
                            f"{h_b64}.{p_b64}".encode(),
                            hashlib.sha256).digest()
        if hmac.compare_digest(b64url(expected), sig_b64):
            return payload
        return None
    return None

def current_user():
    tok = request.cookies.get("session_jwt")
    if not tok:
        return None
    return jwt_decode(tok)

# ---------------------------------------------------------------------------
# Routes publiques
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")

# [FLAG 1] Endpoint cache reference uniquement dans robots.txt + commentaire HTML.
@app.route("/robots.txt")
def robots():
    body = "User-agent: *\nDisallow: /internal/dev-notes\n"
    resp = make_response(body)
    resp.headers["Content-Type"] = "text/plain"
    return resp

@app.route("/internal/dev-notes")
def dev_notes():
    # Flag 1 : simple recon. Donne aussi l'indice pour le flag 2 (JWT).
    return jsonify({
        "flag": FLAGS[1],
        "dev_note": "Auth migrated to JWT (session_jwt cookie). "
                    "TODO: remove legacy 'alg:none' compatibility before prod!",
        "next_hint": "POST /login with guest:guest to get a token."
    })

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or request.form
    u = data.get("username", "")
    p = data.get("password", "")
    user = USERS.get(u)
    if not user or user["password"] != p:
        return jsonify({"error": "invalid credentials"}), 401
    token = jwt_encode({"user": u, "id": user["id"], "role": user["role"]})
    resp = make_response(jsonify({"message": f"welcome {u}", "role": user["role"]}))
    resp.set_cookie("session_jwt", token)
    return resp

@app.route("/profile")
def profile():
    """
    [FLAG 2] Accessible avec role=admin. Un JWT alg:none forge donne l'acces.
    """
    payload = current_user()
    if not payload:
        return jsonify({"error": "no valid session"}), 401
    if payload.get("role") == "admin":
        return jsonify({
            "message": "admin profile unlocked",
            "flag": FLAGS[2],
            "next_hint": "The HS256 secret is short. Crack it, then sign a token "
                         "and browse /api/users/<id>."
        })
    return jsonify({"message": f"profile of {payload.get('user')}",
                    "role": payload.get("role")})

@app.route("/api/whoami")
def whoami():
    payload = current_user()
    if not payload:
        return jsonify({"error": "no session"}), 401
    return jsonify(payload)

# [FLAG 3] Necessite un JWT HS256 VALIDE (signe avec le secret cracke) avec role=admin.
@app.route("/api/admin/console")
def admin_console():
    tok = request.cookies.get("session_jwt", "")
    parts = tok.split(".")
    if len(parts) != 3 or parts[2] == "":
        return jsonify({"error": "this endpoint requires a properly SIGNED token "
                                 "(alg:none rejected here)"}), 403
    payload = jwt_decode(tok)
    if not payload or payload.get("role") != "admin":
        return jsonify({"error": "valid admin signature required"}), 403
    return jsonify({
        "flag": FLAGS[3],
        "console": "NEXUS admin console",
        "next_hint": "Users have private notes at /api/users/<id>. Yours isn't the only id."
    })

# [FLAG 4] IDOR : lit la note privee de n'importe quel user par son id.
@app.route("/api/users/<int:uid>")
def get_user(uid):
    payload = current_user()
    if not payload:
        return jsonify({"error": "no session"}), 401
    # VULN : aucune verification que payload['id'] == uid
    for name, u in USERS.items():
        if u["id"] == uid:
            return jsonify({"username": name, "role": u["role"], "note": u["note"]})
    return jsonify({"error": "not found"}), 404

# ---------------------------------------------------------------------------
# [FLAG 5] Cookie "legacy_role" chiffre en AES-ECB -> attaque cut-and-paste.
# ---------------------------------------------------------------------------
def _aes_ecb_encrypt(plaintext: bytes) -> bytes:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    return AES.new(AES_KEY, AES.MODE_ECB).encrypt(pad(plaintext, 16))

def _aes_ecb_decrypt(ciphertext: bytes) -> bytes:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    return unpad(AES.new(AES_KEY, AES.MODE_ECB).decrypt(ciphertext), 16)

@app.route("/legacy/session")
def legacy_session():
    """
    Emet un cookie ECB encodant 'user=<name>&role=guest'. Comme ECB chiffre
    chaque bloc independamment, le joueur peut rearranger les blocs pour
    fabriquer 'role=admin' (cut-and-paste). Le username est reflechi -> il
    controle l'alignement des blocs.
    """
    name = request.args.get("user", "guest")[:48]
    # Format : "role=guest&user=<name>". 'role=guest&user=' fait 16 octets pile,
    # donc <name> commence sur une frontiere de bloc. Le joueur peut fabriquer
    # un bloc "role=admin&user=" en jouant sur name, puis recopier ce bloc en
    # tete du cookie (cut-and-paste) pour que le DERNIER role= vaille admin.
    plaintext = f"role=guest&user={name}".encode()
    cookie = base64.b64encode(_aes_ecb_encrypt(plaintext)).decode()
    resp = make_response(jsonify({
        "legacy_cookie": cookie,
        "hint": "AES-ECB, block=16. 'role=guest&user=' is exactly one block. "
                "Craft a block '&role=admin' via the reflected 'user' field, "
                "then the last role= wins.",
        "verify_at": "/legacy/verify"
    }))
    return resp

@app.route("/legacy/verify", methods=["POST"])
def legacy_verify():
    data = request.get_json(silent=True) or {}
    blob = data.get("legacy_cookie", "")
    try:
        pt = _aes_ecb_decrypt(base64.b64decode(blob)).decode(errors="replace")
    except Exception:
        return jsonify({"error": "decrypt failed"}), 400
    # parse "user=x&role=y" ; en cas de cle repetee, la DERNIERE gagne
    # (comportement volontaire qui rend le cut-and-paste ECB exploitable).
    fields = {}
    for kv in pt.split("&"):
        if "=" in kv:
            k, v = kv.split("=", 1)
            fields[k] = v
    if fields.get("role", "").rstrip("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f") == "admin":
        return jsonify({"flag": FLAGS[5],
                        "next_hint": "The document vault at /vault uses AES-CBC. "
                                     "Errors are... talkative."})
    return jsonify({"role_seen": fields.get("role"), "message": "not admin yet"})

# ---------------------------------------------------------------------------
# [FLAG 6] Padding oracle AES-CBC sur /vault.
# ---------------------------------------------------------------------------
@app.route("/vault")
def vault():
    # Donne le blob chiffre a dechiffrer via l'oracle.
    secret = f"vault_unlock_code={FLAGS[6]}".encode()
    blob = base64.b64encode(VAULT_IV + _aes_cbc_encrypt(secret, VAULT_KEY, VAULT_IV)).decode()
    return jsonify({
        "encrypted_document": blob,
        "hint": "AES-CBC. First 16 bytes = IV. Submit ciphertext to /vault/open; "
                "padding errors and decrypt errors return different statuses.",
    })

@app.route("/vault/open", methods=["POST"])
def vault_open():
    """
    Oracle : renvoie 200 si padding valide, 400 si padding invalide.
    Permet un padding-oracle attack classique pour recuperer le plaintext.
    """
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    data = request.get_json(silent=True) or {}
    try:
        raw = base64.b64decode(data.get("ciphertext", ""))
        iv, ct = raw[:16], raw[16:]
        pt = AES.new(VAULT_KEY, AES.MODE_CBC, iv).decrypt(ct)
        unpad(pt, 16)  # leve ValueError si padding invalide -> l'oracle
    except ValueError:
        return jsonify({"error": "bad padding"}), 400
    except Exception:
        return jsonify({"error": "decrypt error"}), 400
    return jsonify({"status": "padding ok"}), 200

# ---------------------------------------------------------------------------
# [FLAG 7] Token de reset base sur un PRNG previsible (seed = timestamp).
# ---------------------------------------------------------------------------
@app.route("/reset/request", methods=["POST"])
def reset_request():
    import random
    data = request.get_json(silent=True) or {}
    target = data.get("username", "")
    if target not in USERS:
        return jsonify({"error": "unknown user"}), 404
    seed = int(time.time())
    random.seed(seed)                      # VULN : seed previsible
    token = "".join(random.choice("0123456789abcdef") for _ in range(16))
    # on ne renvoie PAS le token ; le joueur doit le reconstruire depuis le seed
    return jsonify({
        "message": f"reset token generated for {target}",
        "server_time": seed,               # fuite du seed
        "hint": "Token = 16 hex chars from random.seed(server_time). "
                "Reconstruct it and POST to /reset/confirm."
    })

@app.route("/reset/confirm", methods=["POST"])
def reset_confirm():
    import random
    data = request.get_json(silent=True) or {}
    target = data.get("username", "")
    provided = data.get("token", "")
    # Le serveur accepte un token valide pour n'importe quel seed dans une
    # petite fenetre (tolerance reseau) -> attaque deterministe.
    now = int(time.time())
    for seed in range(now - 5, now + 1):
        random.seed(seed)
        expected = "".join(random.choice("0123456789abcdef") for _ in range(16))
        if provided == expected and target in USERS:
            return jsonify({"flag": FLAGS[7],
                            "next_hint": "Admin renders your display name via a template "
                                         "at /api/render?name=..."})
    return jsonify({"error": "invalid or expired token"}), 403

# ---------------------------------------------------------------------------
# [FLAG 8] SSTI (Server-Side Template Injection) Jinja2 sur /api/render.
# ---------------------------------------------------------------------------
@app.route("/api/render")
def render_name():
    from jinja2 import Template
    name = request.args.get("name", "guest")
    # VULN : rendu direct d'une entree utilisateur comme template Jinja.
    try:
        out = Template("Hello " + name + "!").render(FLAG8=FLAGS[8])
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"rendered": out,
                    "hint": "This is rendered server-side with Jinja2. "
                            "{{ }} is evaluated. FLAG8 is in scope."})

# ---------------------------------------------------------------------------
# [FLAG 9] Hash length extension sur une API "signed download".
# ---------------------------------------------------------------------------
# signature = MD5(SECRET || message). Le joueur, connaissant message+signature
# et la longueur du secret (fuite ci-dessous), forge une signature valide pour
# un message etendu contenant 'admin=1' -> hash length extension attack.
LEN_EXT_SECRET = os.environ.get("LENEXT_SECRET", "n3xusS3cr3t42")  # 13 chars (fuite du len)

@app.route("/api/download")
def signed_download():
    sig = request.args.get("sig", "")
    # Le message signe est transmis en HEX (msg_hex) pour supporter les octets
    # bruts du padding MD5 lors d'une attaque length-extension. A defaut,
    # 'file' (texte) est accepte pour l'usage nominal.
    msg_hex = request.args.get("msg_hex")
    if msg_hex is not None:
        try:
            message = bytes.fromhex(msg_hex)
        except ValueError:
            return jsonify({"error": "msg_hex invalid"}), 400
    else:
        file = request.args.get("file", "public.txt")
        message = f"file={file}".encode()

    expected = hashlib.md5(LEN_EXT_SECRET.encode() + message).hexdigest()

    if not sig:
        base_msg = b"file=public.txt"
        base_sig = hashlib.md5(LEN_EXT_SECRET.encode() + base_msg).hexdigest()
        return jsonify({
            "example": {"msg_hex": base_msg.hex(), "sig": base_sig},
            "secret_length": len(LEN_EXT_SECRET),
            "hint": "sig = MD5(secret || message). message starts 'file=public.txt'. "
                    "Use hash length extension to append '&admin=1'; submit the "
                    "forged message as msg_hex + the new sig.",
        })

    if hmac.compare_digest(sig, expected) and b"&admin=1" in message:
        return jsonify({"flag": FLAGS[9],
                        "next_hint": "Final step: assemble the master key at /root/unlock"})
    if hmac.compare_digest(sig, expected):
        return jsonify({"message": "download authorized (not admin)"})
    return jsonify({"error": "bad signature"}), 403

# ---------------------------------------------------------------------------
# [FLAG 10] Etape finale : reconstruit une "master key" a partir de fragments
# obtenus aux etapes precedentes. Recompense la progression complete.
# ---------------------------------------------------------------------------
@app.route("/root/unlock", methods=["POST"])
def root_unlock():
    """
    Le joueur doit fournir les 3 fragments distribues dans les reponses des
    flags 3, 6 et 9 (concatenes). Ici on valide un hash pour ne pas exposer
    l'ordre en clair. Fragment attendu : sha256('nexus'+'vault'+'signed').
    """
    data = request.get_json(silent=True) or {}
    key = data.get("master_key", "")
    expected = hashlib.sha256(b"nexus:vault:signed").hexdigest()
    if key == expected:
        return jsonify({"flag": FLAGS[10],
                        "message": "NEXUS domain fully compromised. Nice chain."})
    return jsonify({
        "error": "wrong master key",
        "hint": "master_key = sha256('nexus:vault:signed') (hex). "
                "This proves you completed the console, vault and signing stages."
    })

@app.route("/healthz")
def healthz():
    return "ok", 200

if __name__ == "__main__":
    # Ecoute sur 0.0.0.0 : indispensable pour que le plugin publie le port.
    app.run(host="0.0.0.0", port=8080)

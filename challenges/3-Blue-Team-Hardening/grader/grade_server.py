#!/usr/bin/env python3
# =============================================================================
#  grade_server.py  -  Service de validation CÔTÉ SERVEUR (HTTP)
#
#  ⚠️ Tourne sur l'HÔTE DOCKER / hôte CTFd, JAMAIS dans le conteneur du joueur.
#  Détient les flags. Quand une instance appelle `getflag N`, le service :
#    1. identifie le conteneur appelant par son IP source (docker inspect) —
#       le joueur ne peut donc réclamer que les flags de SA propre instance ;
#    2. inspecte lui-même l'état du conteneur via `docker exec` (il ne fait
#       jamais confiance au client) ;
#    3. renvoie le flag de la tâche N uniquement si elle est réellement durcie.
#
#  Le flag n'existe donc nulle part dans le conteneur : impossible à extraire
#  par reverse. Le joueur le reçoit une fois le correctif appliqué et le tape
#  dans CTFd.
#
#  Lancement (sur l'hôte docker) :
#     pip install flask
#     python3 grade_server.py --port 9000
#  Mode dev (sans docker, inspecte un dossier local) :
#     python3 grade_server.py --port 9000 --dev-target /chemin/rootfs
# =============================================================================
import argparse
import subprocess

from flask import Flask, request, jsonify

from checks import FLAGS, LABELS, evaluate, DockerInspector, LocalInspector

app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False        # Flask < 2.3
try:
    app.json.ensure_ascii = False          # Flask >= 2.3 / 3.x
except Exception:
    pass
DEV_TARGET = None   # si défini : mode dev, inspection locale
ALLOW_CID = False   # si True : repli sur l'ID de conteneur fourni par le client
                    # (pratique en local/Docker Desktop ; à éviter en multi-équipes)


def container_exists(cid):
    try:
        out = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", cid],
                             capture_output=True, text=True, timeout=10).stdout.strip()
        return out == "true"
    except Exception:
        return False


def resolve_container(req):
    """Identifie le conteneur appelant : par IP source, sinon repli sur cid."""
    cid = container_id_from_ip(req.remote_addr)
    if cid:
        return cid
    if ALLOW_CID:
        claimed = req.values.get("cid", "").strip()
        if claimed and container_exists(claimed):
            return claimed
    return None


def container_id_from_ip(ip):
    """Retrouve l'ID du conteneur dont l'IP réseau == ip (autoritatif)."""
    try:
        ids = subprocess.run(["docker", "ps", "-q"], capture_output=True,
                             text=True, timeout=10).stdout.split()
        for cid in ids:
            out = subprocess.run(
                ["docker", "inspect", "-f",
                 "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", cid],
                capture_output=True, text=True, timeout=10).stdout
            if ip in out.split():
                return cid
    except Exception:
        pass
    return None


@app.route("/flag", methods=["GET", "POST"])
def flag():
    try:
        task = int((request.values.get("task") or "0"))
    except ValueError:
        task = 0
    if task not in FLAGS:
        return jsonify(ok=False, msg="Tâche invalide (1 à 10)."), 400

    # Inspecteur autoritatif : dev (local) ou prod (docker exec sur l'appelant)
    if DEV_TARGET is not None:
        insp = LocalInspector(DEV_TARGET)
    else:
        cid = resolve_container(request)
        if not cid:
            return jsonify(ok=False, msg="Instance non identifiée."), 403
        insp = DockerInspector(cid)

    done = evaluate(insp)
    if task in done:
        return jsonify(ok=True, task=task, label=LABELS[task], flag=FLAGS[task])
    return jsonify(ok=False, task=task, label=LABELS[task],
                   msg="Cette faille n'est pas encore corrigée. Continue puis relance getflag.")


@app.route("/score", methods=["GET"])
def score():
    if DEV_TARGET is not None:
        insp = LocalInspector(DEV_TARGET)
    else:
        cid = resolve_container(request)
        if not cid:
            return jsonify(ok=False, msg="Instance non identifiée."), 403
        insp = DockerInspector(cid)
    return jsonify(ok=True, score=len(evaluate(insp)), total=10)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--dev-target", help="mode dev : inspecte ce dossier au lieu de docker")
    ap.add_argument("--allow-cid", action="store_true",
                    help="repli sur l'ID de conteneur fourni par le client (local/Docker Desktop)")
    args = ap.parse_args()
    DEV_TARGET = args.dev_target
    ALLOW_CID = args.allow_cid
    app.run(host=args.host, port=args.port)

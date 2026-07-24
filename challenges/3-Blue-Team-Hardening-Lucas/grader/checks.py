#!/usr/bin/env python3
# =============================================================================
#  checks.py  -  Logique de contrôle du durcissement (SOURCE DE VÉRITÉ unique)
#
#  Partagé par :
#    - grade.py         (CLI admin, inspection locale ou SSH)
#    - grade_server.py  (service HTTP, inspection via `docker exec`)
#
#  L'inspection passe TOUJOURS par un "Inspector" : le grader lit lui-même
#  l'état réel de l'instance et ne fait jamais confiance au client.
# =============================================================================
import os
import subprocess

# --- FLAGS : présents UNIQUEMENT côté serveur, jamais dans le conteneur ------
FLAGS = {
    1:  "RootMeUp{r00t_l0gin_disabled}",
    2:  "RootMeUp{n0_empty_passw0rds}",
    3:  "RootMeUp{shadow_l0cked_down}",
    4:  "RootMeUp{secrets_perms_600}",
    5:  "RootMeUp{malicious_cron_purged}",
    6:  "RootMeUp{telnet_is_dead}",
    7:  "RootMeUp{no_hidden_r00t_user}",
    8:  "RootMeUp{suid_backdoor_cleared}",
    9:  "RootMeUp{writable_path_secured}",
    10: "RootMeUp{ssh_backdoor_key_removed}",
}

LABELS = {
    1: "SSH root login désactivé", 2: "Mots de passe vides refusés",
    3: "/etc/shadow protégé", 4: "Secret applicatif protégé",
    5: "Persistance planifiée purgée", 6: "Service en clair désactivé",
    7: "Aucun accès admin caché", 8: "Élévation de privilèges corrigée",
    9: "Intégrité du PATH", 10: "Accès distant résiduel",
}


# --- Inspecteurs (façons de lire l'état de l'instance) -----------------------
class LocalInspector:
    """Lit un arbre de fichiers local (préfixe). Pour les tests."""
    def __init__(self, target=""):
        self.target = target or ""
    def read(self, path):
        try:
            with open(self.target + path, "r", errors="replace") as f:
                return f.read()
        except OSError:
            return ""
    def mode(self, path):
        try:
            return os.stat(self.target + path).st_mode & 0o7777
        except OSError:
            return -1
    def exists(self, path):
        return os.path.exists(self.target + path)


class _CmdInspector:
    """Base : inspecte en exécutant des commandes shell (ssh / docker exec)."""
    def _run(self, argv):
        try:
            return subprocess.run(argv, capture_output=True, text=True,
                                  timeout=20).stdout
        except Exception:
            return ""
    def _wrap(self, shell_cmd):
        raise NotImplementedError
    def read(self, path):
        return self._run(self._wrap(f"cat -- {path} 2>/dev/null"))
    def mode(self, path):
        out = self._run(self._wrap(f"stat -c %a -- {path} 2>/dev/null")).strip()
        try:
            return int(out, 8)
        except ValueError:
            return -1
    def exists(self, path):
        return self._run(self._wrap(f"test -e {path} && echo Y")).strip() == "Y"


class SSHInspector(_CmdInspector):
    def __init__(self, conn, port=22):
        self.conn = conn; self.port = port
    def _wrap(self, shell_cmd):
        return ["ssh", "-p", str(self.port), "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=8", self.conn, shell_cmd]


class DockerInspector(_CmdInspector):
    """Inspecte un conteneur par son ID via `docker exec` (autoritatif)."""
    def __init__(self, cid):
        self.cid = cid
    def _wrap(self, shell_cmd):
        return ["docker", "exec", self.cid, "sh", "-c", shell_cmd]


# --- Contrôles ---------------------------------------------------------------
def _directive(insp, path, key, val):
    for line in insp.read(path).splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        p = s.split()
        if len(p) >= 2 and p[0] == key and p[1] == val:
            return True
    return False

def _active_token(insp, path, token):
    for line in insp.read(path).splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.split()[0] == token:
            return True
    return False

def _rogue_uid0(insp, path):
    for line in insp.read(path).splitlines():
        f = line.split(":")
        if len(f) >= 3 and f[2] == "0" and f[0] != "root":
            return True
    return False


def evaluate(insp):
    """Retourne l'ensemble des numéros de tâches réellement durcies."""
    ok = set()
    if _directive(insp, "/etc/ssh/sshd_config", "PermitRootLogin", "no") \
       and not _directive(insp, "/etc/ssh/sshd_config", "PermitRootLogin", "yes"):
        ok.add(1)
    if _directive(insp, "/etc/ssh/sshd_config", "PermitEmptyPasswords", "no") \
       and not _directive(insp, "/etc/ssh/sshd_config", "PermitEmptyPasswords", "yes"):
        ok.add(2)
    m = insp.mode("/etc/shadow")
    if m >= 0 and (m & 0o007) == 0:
        ok.add(3)
    m = insp.mode("/opt/app/.env")
    if m >= 0 and (m & 0o077) == 0:
        ok.add(4)
    if not insp.exists("/etc/cron.d/sysupdate"):
        ok.add(5)
    if not _active_token(insp, "/etc/inetd.conf", "telnet"):
        ok.add(6)
    if not _rogue_uid0(insp, "/etc/passwd"):
        ok.add(7)
    m = insp.mode("/usr/local/bin/oldbackup")
    if m < 0 or (m & 0o4000) == 0:
        ok.add(8)
    m = insp.mode("/usr/local/bin")
    if m >= 0 and (m & 0o002) == 0:
        ok.add(9)
    if not insp.exists("/root/.ssh/authorized_keys") \
       or "ctf-attacker" not in insp.read("/root/.ssh/authorized_keys"):
        ok.add(10)
    return ok

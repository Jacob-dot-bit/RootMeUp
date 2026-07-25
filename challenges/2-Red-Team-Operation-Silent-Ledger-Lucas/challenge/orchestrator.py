#!/usr/bin/env python3
"""
Meridian Fleet Orchestrator (internal tool) - v1.4
Listens on a UNIX socket and accepts a small JSON control protocol used
by IT to manage internal jobs across the fleet. Runs as root because it
needs to be able to restart services on any host.
"""
import base64
import json
import os
import pickle
import socket
import socketserver
import threading

SOCK_PATH = "/run/meridian/orchestrator.sock"
TOKEN_FILE = "/root/.orchestrator_token"

# ---------------------------------------------------------------------------
# Flag 8 lives ONLY in this process's memory.
#
# It is loaded from a root-owned file at startup, and that file is deleted
# immediately afterwards. This means the flag cannot be obtained by any
# arbitrary-file-read primitive (e.g. the cap_dac_read_search binary of flag 7,
# which bypasses DAC read checks but cannot read another process's heap): the
# ONLY way to recover it is to achieve code execution *inside* this process,
# i.e. by actually exploiting the insecure-deserialization vulnerability below.
# ---------------------------------------------------------------------------
FLAG8 = "MISSING"


def _load_flag8():
    global FLAG8
    src = "/root/vault/.flag8"
    try:
        with open(src) as f:
            FLAG8 = f.read().strip()
        os.remove(src)  # scrub from disk; only the in-memory copy remains
    except OSError:
        FLAG8 = "MISSING"


def load_token():
    with open(TOKEN_FILE) as f:
        return f.read().strip()


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data = b""
        while not data.endswith(b"\n"):
            chunk = self.request.recv(4096)
            if not chunk:
                break
            data += chunk

        try:
            msg = json.loads(data.decode().strip())
        except Exception:
            self.request.sendall(b'{"error":"bad json"}\n')
            return

        cmd = msg.get("cmd")

        if cmd == "ping":
            self.request.sendall(b'{"status":"ok","service":"meridian-orchestrator v1.4"}\n')
            return

        token = msg.get("token")
        if token != load_token():
            self.request.sendall(b'{"error":"unauthorized"}\n')
            return

        if cmd == "status":
            self.request.sendall(b'{"status":"ok","fleet":["gw-01","app-01","db-01"],"jobs_running":3}\n')
            return

        if cmd == "restore_config":
            # Restores a previously exported job configuration blob.
            # The blob is a base64-encoded serialized job descriptor.
            try:
                blob = base64.b64decode(msg.get("payload", ""))
                obj = pickle.loads(blob)  # nosec - internal trusted tool (historically)
                self.request.sendall(
                    ('{"status":"ok","restored":%s}\n' % json.dumps(str(obj))).encode()
                )
            except Exception as e:
                self.request.sendall(('{"error":"%s"}\n' % str(e)).encode())
            return

        self.request.sendall(b'{"error":"unknown cmd"}\n')


class ThreadingUnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def main():
    _load_flag8()
    os.makedirs(os.path.dirname(SOCK_PATH), exist_ok=True)
    if os.path.exists(SOCK_PATH):
        os.remove(SOCK_PATH)

    server = ThreadingUnixServer(SOCK_PATH, Handler)
    os.chmod(SOCK_PATH, 0o666)
    server.serve_forever()


if __name__ == "__main__":
    main()

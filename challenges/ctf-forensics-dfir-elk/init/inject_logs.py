#!/usr/bin/env python3
"""
Injecte les logs CTF dans Elasticsearch via l'API bulk.
Remplace le file input Logstash qui est peu fiable en conteneur.
"""
import json
import sys
import time
import urllib.request
import urllib.error

ES_URL = "http://localhost:9200"
LOG_FILE = "/opt/ctf-logs-src/corp_incident.json"
INDEX = "dfir-incident-2024.03.15"

FIELD_MAP = {
    "WIN-ACCT01": "192.168.10.45",
    "APP-SRV01":  "192.168.10.52",
    "DC01":       "192.168.10.10",
}

def wait_for_es():
    print("[INJECT] Waiting for Elasticsearch...")
    while True:
        try:
            r = urllib.request.urlopen(f"{ES_URL}/_cluster/health", timeout=5)
            data = json.loads(r.read())
            if data.get("status") in ("green", "yellow"):
                print("[INJECT] Elasticsearch is up!")
                return
        except Exception:
            pass
        time.sleep(3)

def inject():
    with open(LOG_FILE, "r") as f:
        lines = [l.strip() for l in f if l.strip()]

    print(f"[INJECT] Injecting {len(lines)} documents into {INDEX}...")

    bulk_body = []
    for line in lines:
        try:
            doc = json.loads(line)
        except json.JSONDecodeError as e:
            print(f"[INJECT] Skipping bad line: {e}")
            continue

        # Enrichissement
        doc["environment"]  = "corp.local"
        doc["domain"]       = "CORP"
        doc["ctf_scenario"] = "DFIR-Incident-2024-03-15"
        host = doc.get("host", "")
        if host in FIELD_MAP:
            doc["host_ip"] = FIELD_MAP[host]

        bulk_body.append(json.dumps({"index": {"_index": INDEX}}))
        bulk_body.append(json.dumps(doc))

    payload = "\n".join(bulk_body) + "\n"
    req = urllib.request.Request(
        f"{ES_URL}/_bulk",
        data=payload.encode("utf-8"),
        headers={"Content-Type": "application/x-ndjson"},
        method="POST"
    )
    r = urllib.request.urlopen(req, timeout=30)
    resp = json.loads(r.read())
    if resp.get("errors"):
        errors = [i for i in resp["items"] if i.get("index", {}).get("error")]
        print(f"[INJECT] {len(errors)} errors during bulk insert")
        for e in errors[:3]:
            print(f"[INJECT]   {e}")
    else:
        print(f"[INJECT] Successfully injected {len(lines)} documents!")

if __name__ == "__main__":
    wait_for_es()
    inject()
    print("[INJECT] Done.")

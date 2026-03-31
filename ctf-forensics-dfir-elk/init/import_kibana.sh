#!/bin/sh
# Script d'initialisation Kibana – attend que tout soit prêt puis crée l'index pattern

KIBANA_URL="http://localhost:5601"
ES_URL="http://localhost:9200"

log() { echo "[CTF-INIT] $1"; }

# ── Attendre Elasticsearch ────────────────────────────────────────────────────
log "Waiting for Elasticsearch..."
until curl -s "${ES_URL}/_cluster/health" | grep -q '"status":"green"\|"status":"yellow"'; do
    sleep 5
done
log "Elasticsearch is up!"

# ── Attendre Kibana ───────────────────────────────────────────────────────────
log "Waiting for Kibana..."
until curl -s "${KIBANA_URL}/api/status" | grep -q '"level":"available"'; do
    sleep 5
done
log "Kibana is up!"

# ── Attendre que les logs soient injectés ────────────────────────────────────
log "Waiting for logs to be injected (target: 200+ documents)..."
EXPECTED_DOCS=200
while true; do
    COUNT=$(curl -s "${ES_URL}/dfir-incident-*/_count" 2>/dev/null | grep -o '"count":[0-9]*' | grep -o "[0-9]*")
    COUNT=${COUNT:-0}
    if [ "$COUNT" -ge "$EXPECTED_DOCS" ] 2>/dev/null; then
        log "Injection done: ${COUNT} documents indexed."
        break
    fi
    log "Documents indexed so far: ${COUNT}/${EXPECTED_DOCS} — waiting..."
    sleep 5
done
sleep 2

# ── Créer le data view (API Kibana 8.x) ──────────────────────────────────────
log "Creating data view..."
curl -s -X POST "${KIBANA_URL}/api/data_views/data_view" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d '{
    "data_view": {
      "id": "dfir-incident",
      "title": "dfir-incident-*",
      "timeFieldName": "@timestamp"
    }
  }' > /dev/null

# ── Définir comme data view par défaut ───────────────────────────────────────
curl -s -X POST "${KIBANA_URL}/api/data_views/default" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d '{"data_view_id": "dfir-incident", "force": true}' > /dev/null

# ── Saved Search : tous les events ───────────────────────────────────────────
log "Creating saved searches..."
curl -s -X POST "${KIBANA_URL}/api/saved_objects/search/all-events" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d '{
    "attributes": {
      "title": "📋 All Events (chronological)",
      "columns": ["@timestamp","host","event_id","user","description","category"],
      "sort": [["@timestamp","asc"]],
      "kibanaSavedObjectMeta": {
        "searchSourceJSON": "{\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\",\"query\":{\"match_all\":{}},\"filter\":[]}"
      }
    },
    "references": [{"name":"kibanaSavedObjectMeta.searchSourceJSON.index","type":"index-pattern","id":"dfir-incident"}]
  }' > /dev/null

# ── Saved Search : events réseau ─────────────────────────────────────────────
curl -s -X POST "${KIBANA_URL}/api/saved_objects/search/network-events" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d '{
    "attributes": {
      "title": "🌐 Network Events (5156)",
      "columns": ["@timestamp","host","user","direction","dst_ip","dst_port","protocol","description"],
      "sort": [["@timestamp","asc"]],
      "kibanaSavedObjectMeta": {
        "searchSourceJSON": "{\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\",\"query\":{\"match\":{\"event_id\":5156}},\"filter\":[]}"
      }
    },
    "references": [{"name":"kibanaSavedObjectMeta.searchSourceJSON.index","type":"index-pattern","id":"dfir-incident"}]
  }' > /dev/null

# ── Saved Search : events process ────────────────────────────────────────────
curl -s -X POST "${KIBANA_URL}/api/saved_objects/search/process-events" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d '{
    "attributes": {
      "title": "⚙️ Process Creation (4688)",
      "columns": ["@timestamp","host","user","process_name","parent_process","command_line","description"],
      "sort": [["@timestamp","asc"]],
      "kibanaSavedObjectMeta": {
        "searchSourceJSON": "{\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\",\"query\":{\"match\":{\"event_id\":4688}},\"filter\":[]}"
      }
    },
    "references": [{"name":"kibanaSavedObjectMeta.searchSourceJSON.index","type":"index-pattern","id":"dfir-incident"}]
  }' > /dev/null

# ── Saved Search : authentifications ─────────────────────────────────────────
curl -s -X POST "${KIBANA_URL}/api/saved_objects/search/auth-events" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d '{
    "attributes": {
      "title": "🔐 Authentication Events (4624/4648)",
      "columns": ["@timestamp","host","user","logon_type","source_ip","target_user","target_host","description"],
      "sort": [["@timestamp","asc"]],
      "kibanaSavedObjectMeta": {
        "searchSourceJSON": "{\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\",\"query\":{\"bool\":{\"should\":[{\"match\":{\"event_id\":4624}},{\"match\":{\"event_id\":4648}}]}},\"filter\":[]}"
      }
    },
    "references": [{"name":"kibanaSavedObjectMeta.searchSourceJSON.index","type":"index-pattern","id":"dfir-incident"}]
  }' > /dev/null

# ── Saved Search : Kerberos ───────────────────────────────────────────────────
curl -s -X POST "${KIBANA_URL}/api/saved_objects/search/kerberos-events" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d '{
    "attributes": {
      "title": "🎟️ Kerberos Events (4769)",
      "columns": ["@timestamp","host","user","service_name","ticket_encryption","ticket_options","client_ip","description"],
      "sort": [["@timestamp","asc"]],
      "kibanaSavedObjectMeta": {
        "searchSourceJSON": "{\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\",\"query\":{\"match\":{\"event_id\":4769}},\"filter\":[]}"
      }
    },
    "references": [{"name":"kibanaSavedObjectMeta.searchSourceJSON.index","type":"index-pattern","id":"dfir-incident"}]
  }' > /dev/null

# ── Saved Search : Account Management ────────────────────────────────────────
curl -s -X POST "${KIBANA_URL}/api/saved_objects/search/account-mgmt" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d '{
    "attributes": {
      "title": "👤 Account Management (4720/4728/4742/4764/5136)",
      "columns": ["@timestamp","host","user","new_account","target_account","target_user_sid","group_name","attribute_value","description"],
      "sort": [["@timestamp","asc"]],
      "kibanaSavedObjectMeta": {
        "searchSourceJSON": "{\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\",\"query\":{\"bool\":{\"should\":[{\"match\":{\"event_id\":4720}},{\"match\":{\"event_id\":4728}},{\"match\":{\"event_id\":4742}},{\"match\":{\"event_id\":4764}},{\"match\":{\"event_id\":5136}}]}},\"filter\":[]}"
      }
    },
    "references": [{"name":"kibanaSavedObjectMeta.searchSourceJSON.index","type":"index-pattern","id":"dfir-incident"}]
  }' > /dev/null

# ── Saved Search : Process Access (Sysmon 10) ─────────────────────────────────
curl -s -X POST "${KIBANA_URL}/api/saved_objects/search/process-access" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d '{
    "attributes": {
      "title": "🔍 Process Access (Sysmon Event 10)",
      "columns": ["@timestamp","host","user","source_process","target_process","call_trace","description"],
      "sort": [["@timestamp","asc"]],
      "kibanaSavedObjectMeta": {
        "searchSourceJSON": "{\"indexRefName\":\"kibanaSavedObjectMeta.searchSourceJSON.index\",\"query\":{\"match\":{\"event_id\":10}},\"filter\":[]}"
      }
    },
    "references": [{"name":"kibanaSavedObjectMeta.searchSourceJSON.index","type":"index-pattern","id":"dfir-incident"}]
  }' > /dev/null

log "✅ Kibana initialized! Index pattern and saved searches are ready."
log "Access Kibana at http://localhost:5601"

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV ES_VERSION=8.11.0
ENV LS_VERSION=1:8.11.0-1

# ── Dépendances système ──────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y \
    wget curl gnupg supervisor \
    && rm -rf /var/lib/apt/lists/*

# ── Java (requis par ES + Logstash) ─────────────────────────────────────────
RUN apt-get update && apt-get install -y default-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

# ── Clé GPG Elastic + dépôt ─────────────────────────────────────────────────
RUN wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch \
    | gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] \
    https://artifacts.elastic.co/packages/8.x/apt stable main" \
    > /etc/apt/sources.list.d/elastic-8.x.list

# ── Installation Elasticsearch + Kibana + Logstash ───────────────────────────
RUN apt-get update && apt-get install -y \
    elasticsearch=${ES_VERSION} \
    kibana=${ES_VERSION} \
    logstash=${LS_VERSION} \
    && rm -rf /var/lib/apt/lists/*

# ── Configuration Elasticsearch ──────────────────────────────────────────────
RUN echo "network.host: 0.0.0.0" > /etc/elasticsearch/elasticsearch.yml \
    && echo "discovery.type: single-node" >> /etc/elasticsearch/elasticsearch.yml \
    && echo "xpack.security.enabled: false" >> /etc/elasticsearch/elasticsearch.yml \
    && echo "xpack.security.http.ssl.enabled: false" >> /etc/elasticsearch/elasticsearch.yml \
    && echo "xpack.security.enrollment.enabled: false" >> /etc/elasticsearch/elasticsearch.yml \
    && echo 'ES_JAVA_OPTS="-Xms512m -Xmx512m"' >> /etc/default/elasticsearch \
    && rm -rf /etc/elasticsearch/certs \
    && rm -f /etc/elasticsearch/elasticsearch.keystore \
    && mkdir -p /var/lib/elasticsearch /var/log/elasticsearch \
        /usr/share/elasticsearch/logs /usr/share/elasticsearch/data \
    && chown -R elasticsearch:elasticsearch \
        /etc/elasticsearch \
        /var/lib/elasticsearch \
        /var/log/elasticsearch \
        /usr/share/elasticsearch

# ── Configuration Kibana ─────────────────────────────────────────────────────
RUN echo 'server.host: "0.0.0.0"' > /etc/kibana/kibana.yml \
    && echo 'elasticsearch.hosts: ["http://localhost:9200"]' >> /etc/kibana/kibana.yml \
    && echo 'xpack.security.enabled: false' >> /etc/kibana/kibana.yml \
    && echo 'telemetry.enabled: false' >> /etc/kibana/kibana.yml \
    && echo 'xpack.fleet.enabled: false' >> /etc/kibana/kibana.yml \
    && echo 'xpack.apm.enabled: false' >> /etc/kibana/kibana.yml \
    && echo 'xpack.securitySolution.enabled: false' >> /etc/kibana/kibana.yml \
    && rm -f /etc/kibana/kibana.keystore \
    && mkdir -p /var/lib/kibana /var/log/kibana /run/kibana \
    && chown -R kibana:kibana \
        /etc/kibana \
        /var/lib/kibana \
        /var/log/kibana \
        /run/kibana \
        /usr/share/kibana

# ── Configuration Logstash ───────────────────────────────────────────────────
RUN mkdir -p /usr/share/logstash/data /var/log/logstash /var/lib/logstash \
    && chown -R logstash:logstash \
        /usr/share/logstash \
        /etc/logstash \
        /var/log/logstash \
        /var/lib/logstash

# ── Logstash configuration globale ───────────────────────────────────────────
RUN mkdir -p /usr/share/logstash/config \
    && echo 'pipeline.ecs_compatibility: disabled' > /usr/share/logstash/config/logstash.yml \
    && echo 'xpack.monitoring.enabled: false' >> /usr/share/logstash/config/logstash.yml \
    && chown logstash:logstash /usr/share/logstash/config/logstash.yml

# ── Logstash pipeline ────────────────────────────────────────────────────────
COPY pipeline/logstash.conf /etc/logstash/conf.d/logstash.conf
RUN chown logstash:logstash /etc/logstash/conf.d/logstash.conf

# ── Logs du challenge ────────────────────────────────────────────────────────
COPY logs/ /opt/ctf-logs-src/
RUN chmod -R 644 /opt/ctf-logs-src/*.json && chmod 755 /opt/ctf-logs-src/

# ── Supervisord configuration ────────────────────────────────────────────────
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# ── Script d'injection des logs ──────────────────────────────────────────────
COPY init/inject_logs.py /opt/inject_logs.py
RUN chmod +x /opt/inject_logs.py

# ── Script init Kibana ────────────────────────────────────────────────────────
COPY init/import_kibana.sh /opt/import_kibana.sh
RUN chmod +x /opt/import_kibana.sh

# ── Port exposé (Kibana) ─────────────────────────────────────────────────────
EXPOSE 5601

CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
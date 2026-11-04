ARG PRODUCTION_BASE
FROM ${PRODUCTION_BASE}
COPY crowdsec /usr/local/bin/crowdsec
COPY seed/config /usr/share/nginx-security-engine/config
COPY seed/data /usr/share/nginx-security-engine/data
COPY control.py appsec.py hub_update.py start.py initialize.py /usr/local/lib/nginx-ui-security/engine/
COPY supervisor.conf /etc/supervisor/engine.conf
RUN chmod 0755 /usr/local/bin/crowdsec && test -x /usr/bin/cscli
ENTRYPOINT ["/usr/bin/supervisord","-c","/etc/supervisor/engine.conf"]

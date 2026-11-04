# Add AppSec transport to an explicitly pinned, verified production runtime.
ARG PRODUCTION_BASE
FROM ${PRODUCTION_BASE}
COPY security-access.lua nginx_ui_appsec.lua nginx_ui_security_events.lua /usr/local/lua/nginx-ui/
COPY crowdsec-init.conf /usr/local/share/nginx-ui-security/crowdsec-init.conf
COPY audit_normalizer.py /usr/local/lib/nginx-ui-security/audit_normalizer.py
ENV SECURITY_CENTER_APPSEC_ENABLED=true
LABEL org.opencontainers.image.description="NGINX UI with per-vhost CrowdSec AppSec"

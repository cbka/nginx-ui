# syntax=docker/dockerfile:1
# Build context is repository root. Require a digest and an immutable apt snapshot.
ARG DEBIAN_BASE
FROM ${DEBIAN_BASE}
ARG TARGETARCH=amd64
ARG DEBIAN_SNAPSHOT
RUN test "$TARGETARCH" = amd64 && test -n "$DEBIAN_SNAPSHOT" \
    && rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*.sources \
    && printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/%s/ trixie main\ndeb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/%s/ trixie-security main\n' "$DEBIAN_SNAPSHOT" "$DEBIAN_SNAPSHOT" > /etc/apt/sources.list \
    && apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl nginx libnginx-mod-http-lua libnginx-mod-http-modsecurity \
        libnginx-mod-stream modsecurity-crs lua-cjson supervisor python3 \
    && rm -rf /var/lib/apt/lists/*
# Verified official release artifacts. No curl|shell installers or runtime downloads.
RUN mkdir -p /tmp/security /usr/local/lua/crowdsec/resty /var/lib/crowdsec/lua/templates \
    && curl -fsSL https://github.com/crowdsecurity/cs-nginx-bouncer/releases/download/v1.2.3/crowdsec-nginx-bouncer.tgz -o /tmp/security/bouncer.tgz \
    && echo '8cb0c176f01bda3a5fc5493d20bcd7261630c7dfbd60c00b2bff8eefc8fe84d5  /tmp/security/bouncer.tgz' | sha256sum -c - \
    && tar -xzf /tmp/security/bouncer.tgz -C /tmp/security \
    && cp -a /tmp/security/crowdsec-nginx-bouncer-v1.2.3/lua-mod/lib/. /usr/local/lua/crowdsec/ \
    && cp -a /tmp/security/crowdsec-nginx-bouncer-v1.2.3/lua-mod/templates/. /var/lib/crowdsec/lua/templates/ \
    && mkdir -p /usr/local/share/nginx-ui-security \
    && cp /tmp/security/crowdsec-nginx-bouncer-v1.2.3/nginx/crowdsec_nginx.conf /usr/local/share/nginx-ui-security/crowdsec-http.conf.example \
    && cp /tmp/security/crowdsec-nginx-bouncer-v1.2.3/lua-mod/config_example.conf /usr/local/share/nginx-ui-security/bouncer.conf.example \
    && curl -fsSL https://github.com/ledgetech/lua-resty-http/archive/refs/tags/v0.17.2.tar.gz -o /tmp/security/http.tgz \
    && echo '3da18ca8582243eff28302591e36651dc7fab046e77336aa4a6fa718bccce4a2  /tmp/security/http.tgz' | sha256sum -c - \
    && tar -xzf /tmp/security/http.tgz -C /tmp/security \
    && cp /tmp/security/lua-resty-http-0.17.2/lib/resty/*.lua /usr/local/lua/crowdsec/resty/ \
    && curl -fsSL https://github.com/crowdsecurity/crowdsec/releases/download/v1.8.2/crowdsec-release.tgz -o /tmp/security/cs.tgz \
    && echo '6e0b2add0ff3231dca3db7146834d7fea028215b915e2da39ebe30fc9f11436f  /tmp/security/cs.tgz' | sha256sum -c - \
    && tar -xzf /tmp/security/cs.tgz -C /tmp/security crowdsec-v1.8.2/cmd/crowdsec-cli/cscli \
    && install -m 0755 /tmp/security/crowdsec-v1.8.2/cmd/crowdsec-cli/cscli /usr/bin/cscli \
    && rm -rf /tmp/security
RUN mkdir -p /tmp/security \
    && curl -fsSL https://github.com/openresty/lua-resty-string/archive/refs/tags/v0.16.tar.gz -o /tmp/security/string.tgz \
    && echo '77f006a97fd4a3be4a82dcf2d5f1482e399b70fb35454c5b5ad4b97ff1dded0d  /tmp/security/string.tgz' | sha256sum -c - \
    && tar -xzf /tmp/security/string.tgz -C /tmp/security \
    && cp /tmp/security/lua-resty-string-0.16/lib/resty/*.lua /usr/local/lua/crowdsec/resty/ \
    && rm -rf /tmp/security
COPY packaging/security/audit_reader.py packaging/security/audit_normalizer.py /usr/local/lib/nginx-ui-security/
COPY packaging/security/security-access.lua packaging/security/nginx_ui_security_events.lua /usr/local/lua/nginx-ui/
COPY packaging/security/crowdsec-init.conf /usr/local/share/nginx-ui-security/crowdsec-init.conf
COPY packaging/security/artifacts/nginx-ui /usr/local/bin/nginx-ui
COPY packaging/security/entrypoint.sh packaging/security/restart.sh packaging/security/smoke.sh /usr/local/sbin/
COPY packaging/security/supervisord.conf /etc/supervisor/security-runtime.conf
COPY packaging/security/modsecurity-base.conf packaging/security/loader.conf packaging/security/initial-policy.conf /usr/local/share/nginx-ui-security/
RUN chmod 0755 /usr/local/bin/nginx-ui /usr/local/sbin/entrypoint.sh /usr/local/sbin/restart.sh /usr/local/sbin/smoke.sh \
    && mkdir -p /run/nginx-ui /etc/nginx/security-center /usr/local/etc/nginx-ui /etc/modsecurity /var/log/nginx/modsecurity \
    && chmod 0750 /var/log/nginx/modsecurity \
    && test ! -e /etc/modsecurity/modsecurity.conf \
    && cp /usr/local/share/nginx-ui-security/modsecurity-base.conf /etc/modsecurity/modsecurity.conf \
    && dpkg-query -W > /usr/local/share/nginx-ui-security/packages.lock \
    && /usr/local/sbin/smoke.sh
ENV NGINX_UI_WORKING_DIR=/run/nginx-ui TZ=UTC
EXPOSE 80 443 9000
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/sbin/entrypoint.sh"]

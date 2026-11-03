# Production module parity and compatibility aliases; repository-root build context.
# Supply the verified security runtime image ID/digest explicitly.
ARG SECURITY_BASE
FROM ${SECURITY_BASE}
# These exact runtime versions were observed on nginx-peer-2 on 2026-11-03.
# Reuse the base image's immutable Debian snapshot; never switch to live mirrors.
COPY packaging/security/production/runtime-modules.lock /usr/local/share/nginx-ui-security/runtime-modules.lock
RUN test "$(dpkg-query -W -f='${Version}' nginx)" = '1.26.3-3+deb13u10' \
    && grep -q 'snapshot.debian.org/archive/debian/' /etc/apt/sources.list \
    && apt-get update \
    && xargs -r apt-get install -y --no-install-recommends --no-remove < /usr/local/share/nginx-ui-security/runtime-modules.lock \
    && test "$(dpkg-query -W -f='${Version}' nginx)" = '1.26.3-3+deb13u10' \
    && while IFS='=' read -r package expected; do \
         test "$(dpkg-query -W -f='${Version}' "$package")" = "$expected" || exit 1; \
       done < /usr/local/share/nginx-ui-security/runtime-modules.lock \
    && dpkg-query -W > /usr/local/share/nginx-ui-security/packages.lock \
    && rm -rf /var/lib/apt/lists/*
COPY packaging/security/production/nginx-ui-entrypoint packaging/security/production/nginx-ui-nginx-restart packaging/security/production/nginx-ui-disable-nchan /usr/local/sbin/
RUN chmod 0755 /usr/local/sbin/nginx-ui-entrypoint /usr/local/sbin/nginx-ui-nginx-restart /usr/local/sbin/nginx-ui-disable-nchan \
    && test -x /usr/local/sbin/entrypoint.sh \
    && test -x /usr/local/sbin/restart.sh \
    && test -f /etc/supervisor/security-runtime.conf
ENTRYPOINT ["/usr/local/sbin/nginx-ui-entrypoint"]

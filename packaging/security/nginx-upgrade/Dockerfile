# Runtime source overlay: all 29 modules rebuilt with the same NGINX ABI.
# Base must be the exact existing production image digest.
ARG RUNTIME_BASE
FROM ${RUNTIME_BASE}
COPY output/ /tmp/nginx130/
COPY nginx.sha256 sources.sha256 module-sources.lock /usr/local/share/nginx-ui-security/nginx-1.30.6/
RUN set -eu; \
    mkdir -p /usr/local/share/nginx-ui-security/debian-original; \
    dpkg-divert --local --rename --add --divert /usr/local/share/nginx-ui-security/debian-original/nginx /usr/sbin/nginx; \
    install -m 0755 /tmp/nginx130/nginx /usr/sbin/nginx; \
    for file in /usr/lib/nginx/modules/*.so; do \
      name="$(basename "$file")"; \
      test -s "/tmp/nginx130/$name"; \
      dpkg-divert --local --rename --add --divert "/usr/local/share/nginx-ui-security/debian-original/$name" "$file"; \
      install -m 0644 "/tmp/nginx130/$name" "$file"; \
    done; \
    for rel in nginx.pm auto/nginx/nginx.so; do \
      path="/usr/lib/x86_64-linux-gnu/perl5/5.40/$rel"; \
      dpkg-divert --local --rename --add --divert "$path.debian-original" "$path"; \
    done; \
    cp /tmp/nginx130/perl-lib/nginx.pm /usr/lib/x86_64-linux-gnu/perl5/5.40/nginx.pm; \
    cp /tmp/nginx130/perl-auto/nginx/nginx.so /usr/lib/x86_64-linux-gnu/perl5/5.40/auto/nginx/nginx.so; \
    nginx -v 2>&1 | grep -Fx 'nginx version: nginx/1.30.6'; \
    nginx -t; \
    sha256sum /usr/sbin/nginx /usr/lib/nginx/modules/*.so > /usr/local/share/nginx-ui-security/nginx-1.30.6/runtime.sha256; \
    rm -rf /tmp/nginx130
LABEL org.nginx-ui.security.nginx.version="1.30.6"

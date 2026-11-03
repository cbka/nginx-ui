# Overlay hourly CRS maintenance onto an already verified immutable runtime.
ARG PRODUCTION_BASE
FROM ${PRODUCTION_BASE}
COPY crs_update.py /usr/local/lib/nginx-ui-security/crs_update.py
COPY supervisor.conf /tmp/crs-supervisor.conf
RUN python3 -c 'from pathlib import Path; import shutil; p=Path("/usr/share/modsecurity-crs"); b=p.with_name("modsecurity-crs.image"); shutil.move(str(p),str(b)); p.symlink_to(b)' \
    && cat /tmp/crs-supervisor.conf >> /etc/supervisor/security-runtime.conf \
    && rm /tmp/crs-supervisor.conf \
    && sed -i '\|^/usr/sbin/nginx -t$|i /usr/bin/python3 /usr/local/lib/nginx-ui-security/crs_update.py --restore' /usr/local/sbin/entrypoint.sh

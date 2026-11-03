#!/bin/sh
set -eu
umask 027
mkdir -p /run/nginx-ui /var/log/nginx
# Never initialize or replace persisted production state implicitly.
if [ ! -s /usr/local/etc/nginx-ui/app.ini ]; then
    echo 'Mount initialized Nginx UI state at /usr/local/etc/nginx-ui/app.ini.' >&2
    exit 1
fi
/usr/sbin/nginx -t
exec /usr/bin/supervisord -c /etc/supervisor/security-runtime.conf

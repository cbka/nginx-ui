#!/bin/sh
set -eu
/usr/sbin/nginx -t
exec /usr/bin/supervisorctl -c /etc/supervisor/security-runtime.conf restart nginx

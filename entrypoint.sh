#!/usr/bin/env sh
set -e

mkdir -p /var/lib/mkbox/files
mkdir -p /var/run/mkbox
chown -R mkbox:mkbox /var/lib/mkbox /var/run/mkbox
chmod 700 /var/lib/mkbox
chmod 755 /var/run /var/run/mkbox

exec gosu mkbox:mkbox /app/mkbox "$@"



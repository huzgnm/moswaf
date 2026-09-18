#!/bin/sh
#
# Start as root only long enough to own the directories, then hand the control
# plane to an unprivileged user.
#
# The chown is what makes this safe to roll out. The site and certificate
# directories are Docker volumes, and on an installation that predates this image
# they already exist owned by root - a container that simply started as a
# non-root user would find them unwritable and fail to publish any configuration,
# turning a hardening change into an outage on every existing install.
set -eu

USER_NAME=moswaf

for dir in "${MOSWAF_SITES_DIR:-/etc/moswaf/sites}" \
           "${MOSWAF_CERTS_DIR:-/etc/moswaf/certs}" \
           "${MOSWAF_ADMIN_TLS_DIR:-/etc/moswaf/admin-tls}"; do
    [ -d "$dir" ] || mkdir -p "$dir"
    # Best effort: a read-only mount is not ours to change, and failing here would
    # stop a control plane that may well be able to run perfectly well anyway.
    chown -R "$USER_NAME:$USER_NAME" "$dir" 2>/dev/null || true
done

# exec, so the control plane becomes PID 1 and Docker's SIGTERM reaches it
# directly - a shell in between swallows the signal and the container is killed
# after the timeout instead of shutting down.
exec su-exec "$USER_NAME:$USER_NAME" /moswafd "$@"

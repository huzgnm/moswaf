# ---------------------------------------------------------------
# MosWAF data plane: OpenResty plus the Lua engine.
# alpine-fat already ships luajit, lua-resty-core, lua-resty-string (sha256),
# lua-resty-redis, lua-cjson and the headers-more module.
# ---------------------------------------------------------------
FROM openresty/openresty:1.27.1.2-alpine-fat

RUN apk add --no-cache bash curl openssl tzdata ca-certificates coreutils \
    && mkdir -p /var/log/moswaf /etc/moswaf/sites /etc/moswaf/certs \
                /usr/local/moswaf/ssl /var/www/acme

COPY dataplane/lua/       /usr/local/moswaf/lua/
COPY dataplane/conf/      /usr/local/moswaf/conf/
COPY dataplane/entrypoint.sh /usr/local/moswaf/entrypoint.sh

RUN chmod +x /usr/local/moswaf/entrypoint.sh

ENV MOSWAF_CONF_DIR=/usr/local/moswaf/conf

EXPOSE 80 443 8081

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8081/healthz || exit 1

ENTRYPOINT ["/usr/local/moswaf/entrypoint.sh"]

# Caddy with the Cloudflare DNS plugin, for DNS-01 wildcard certificates
# (TLS_MODE=wildcard). Built locally — no published image required. install.sh
# builds it and sets CADDY_IMAGE to the resulting tag; every other TLS_MODE
# uses the stock caddy:2-alpine (the CADDY_IMAGE default).
#
#   docker build -f caddy/Dockerfile -t airlock-caddy-local .
FROM caddy:2-builder AS build
RUN xcaddy build --with github.com/caddy-dns/cloudflare

FROM caddy:2-alpine
COPY --from=build /usr/bin/caddy /usr/bin/caddy

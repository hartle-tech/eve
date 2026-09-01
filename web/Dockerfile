# eve.hartle.tech — the landing site.
#
# Build context is the REPOSITORY ROOT, not this directory:
#
#     podman build --platform linux/amd64 -f web/Dockerfile -t eve-site .
#
# because the site's /docs is rendered from docs/*.md at build time rather than
# kept as a second copy under web/. One source, so the pages cannot drift from
# the files the repository ships.
#
# --platform matters: the cluster node is x86_64 and a workstation-built arm64
# image lands as a CrashLoopBackOff with `exec format error`, which reads like a
# broken image rather than a wrong architecture.

# The README is a landing page; the depth lives in docs/*.md. This stage turns
# those same files into /docs on the site.
FROM python:3-alpine AS docs
WORKDIR /build
COPY docs/ docs/
COPY web/render-docs.py .
RUN python3 render-docs.py docs out

FROM caddy:2-alpine

# Drop CAP_NET_BIND_SERVICE from the caddy binary. Under the cluster's
# securityContext (drop:[ALL] + allowPrivilegeEscalation:false +
# runAsNonRoot:true) an fcap-bearing binary fails to exec with EPERM under
# NoNewPrivs. We listen on :8080, so no low-port bind is needed anyway.
USER root
RUN setcap -r /usr/bin/caddy || true

WORKDIR /srv

COPY web/ /srv/
COPY --from=docs /build/out/ /srv/docs/
COPY NOTICE /srv/NOTICE.txt

# Config is not content. `_docs` is a local render for eyeballing the pages
# before a build; the image takes its copy from the docs stage instead.
RUN rm -rf /srv/_docs \
    && rm -f /srv/Caddyfile /srv/Dockerfile /srv/render-docs.py \
    && find /srv -name '._*' -delete \
    && find /srv -name '.DS_Store' -delete

COPY web/Caddyfile /etc/caddy/Caddyfile

USER nobody
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=2s \
  CMD wget --quiet --spider http://127.0.0.1:8080/ || exit 1

CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]

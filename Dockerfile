FROM ghcr.io/mr-pmillz/alpine-bash-tini:latest

ARG TARGETPLATFORM

COPY entrypoint.sh /entrypoint.sh
COPY $TARGETPLATFORM/sj /usr/local/bin/sj
RUN chmod +x /entrypoint.sh /usr/local/bin/sj

ENTRYPOINT ["/sbin/tini", "--", "/entrypoint.sh"]
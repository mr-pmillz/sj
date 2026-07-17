FROM alpine:3.24.1

ARG TARGETPLATFORM

RUN apk add --no-cache ca-certificates tini \
    && addgroup -S -g 10001 sj \
    && adduser -S -D -H -u 10001 -G sj sj

COPY $TARGETPLATFORM/sj /usr/local/bin/sj
RUN chmod 0755 /usr/local/bin/sj

USER 10001:10001
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/sj"]

FROM gcr.io/distroless/static-debian12:nonroot

ARG TARGETOS
ARG TARGETARCH
COPY ${TARGETOS}/${TARGETARCH}/sj /usr/local/bin/sj

ENTRYPOINT ["/usr/local/bin/sj"]

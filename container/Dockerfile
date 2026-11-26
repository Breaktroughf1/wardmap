# Wardmap container image. Built by .github/workflows/container.yml from the
# Sigstore-verified release archives; nothing is compiled here.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG TARGETOS
ARG TARGETARCH
COPY dist/${TARGETOS}_${TARGETARCH}/wardmap /usr/local/bin/wardmap

LABEL org.opencontainers.image.title="wardmap" \
      org.opencontainers.image.description="Map what one compromised CI credential can reach: GitHub Actions secrets and AWS, Azure and GCP roles via OIDC" \
      org.opencontainers.image.source="https://github.com/Breaktroughf1/wardmap" \
      org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /src
ENTRYPOINT ["/usr/local/bin/wardmap"]
CMD ["--help"]

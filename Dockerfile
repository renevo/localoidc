# GoReleaser supplies prebuilt binaries, not the repository, as the build context.
FROM scratch
ARG TARGETPLATFORM
COPY --chmod=0555 ${TARGETPLATFORM}/localoidc /localoidc
USER 65532:65532
ENTRYPOINT ["/localoidc"]

# syntax=docker/dockerfile:1

# ---- build ------------------------------------------------------------------
FROM golang:1.23-alpine AS build

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

WORKDIR /src

# Dependencies first, so a source-only change reuses the module layer.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0 is what makes the binary runnable on scratch: no libc, no
# dynamic loader, nothing for the final image to provide.
ENV CGO_ENABLED=0
RUN go build -trimpath \
      -ldflags "-s -w \
        -X github.com/dotMuny/EnvLeak/internal/buildinfo.Version=${VERSION} \
        -X github.com/dotMuny/EnvLeak/internal/buildinfo.Commit=${COMMIT} \
        -X github.com/dotMuny/EnvLeak/internal/buildinfo.Date=${DATE}" \
      -o /out/envleak ./cmd/envleak

# ---- runtime ----------------------------------------------------------------
FROM scratch

# envleak makes no network calls, so it needs no CA bundle. It does need
# /etc/passwd to run as a non-root user, and a tmp directory for nothing at
# all — both come from the build stage rather than from a base image.
COPY --from=build /etc/passwd /etc/passwd
COPY --from=build /out/envleak /usr/local/bin/envleak

# 65532 is the conventional "nonroot" uid; the container only ever needs read
# access to the mounted repository.
USER 65532:65532
WORKDIR /repo

ENTRYPOINT ["/usr/local/bin/envleak"]
CMD ["scan", "/repo"]

LABEL org.opencontainers.image.title="envleak" \
      org.opencontainers.image.description="Find leaked secrets in a Git repository's working tree and history" \
      org.opencontainers.image.source="https://github.com/dotMuny/EnvLeak" \
      org.opencontainers.image.licenses="MIT"

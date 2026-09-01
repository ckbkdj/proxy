# syntax=docker/dockerfile:1.7

FROM golang:1.23.6-bookworm AS build
WORKDIR /src

ARG VERSION=dev
ARG COMMIT=unknown

COPY go.mod ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod tidy && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
      -o /out/riskd ./cmd/riskd

FROM gcr.io/distroless/base-debian12:nonroot
WORKDIR /app
COPY --from=build /out/riskd /usr/local/bin/riskd

USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/riskd"]

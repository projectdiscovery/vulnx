package vulnx

import (
	"slices"
	"testing"
)

// TestDockerfileImages reads FROM lines: build stages are not images, scratch is none, --platform is passed over,
// ARG defaults fill variables, a digest stays, and a variable with no value is unresolved.
func TestDockerfileImages(t *testing.T) {
	refs, unresolved := dockerfileImages([]byte(`# syntax=docker/dockerfile:1
ARG GO_VERSION=1.22
ARG BASE="debian:12-slim"
ARG REGISTRY
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS builder
RUN go build -o /app . \
    && echo built
FROM builder AS test
FROM ${BASE}
COPY --from=builder /app /app
FROM scratch AS final
FROM gcr.io/distroless/static@sha256:aa11bb
FROM ${REGISTRY}/tools:1
FROM ${MISSING:-alpine:3.20}
from Builder
`))
	if want := []string{"golang:1.22-alpine", "debian:12-slim", "gcr.io/distroless/static@sha256:aa11bb", "alpine:3.20"}; !slices.Equal(refs, want) {
		t.Errorf("refs %q, want %q", refs, want)
	}
	if want := []string{"${REGISTRY}/tools:1"}; !slices.Equal(unresolved, want) {
		t.Errorf("unresolved %q, want %q", unresolved, want)
	}
}

// TestComposeImages reads services' images, with ${VAR:-default} resolved and a service built here left out.
func TestComposeImages(t *testing.T) {
	refs, unresolved, err := composeImages([]byte(`services:
  db:
    image: postgres:16
  cache:
    image: "redis:${REDIS_TAG:-7}"
  app:
    build: .
    image: myorg/app:dev
  worker:
    build:
      context: ./worker
  private:
    image: ${REGISTRY}/private:1
  web:
    image: nginx:${NGINX-1.27}
  again:
    image: postgres:16
`))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"postgres:16", "redis:7", "nginx:1.27"}; !slices.Equal(refs, want) {
		t.Errorf("refs %q, want %q", refs, want)
	}
	if want := []string{"${REGISTRY}/private:1"}; !slices.Equal(unresolved, want) {
		t.Errorf("unresolved %q, want %q", unresolved, want)
	}
	if _, _, err := composeImages([]byte("services: [")); err == nil {
		t.Error("a broken compose file")
	}
}

func TestImageFileNames(t *testing.T) {
	for name, want := range map[string]bool{"Dockerfile": true, "Containerfile": true, "api.Dockerfile": true, "Dockerfile.dev": true,
		"dockerfile.go": false, "Makefile": false} {
		if dockerfileName(name) != want {
			t.Errorf("dockerfile %s", name)
		}
	}
	for name, want := range map[string]bool{"compose.yaml": true, "compose.yml": true, "compose.override.yaml": true,
		"docker-compose.yml": true, "docker-compose.prod.yaml": true, "composer.json": false, "compose.json": false} {
		if composeName(name) != want {
			t.Errorf("compose %s", name)
		}
	}
}

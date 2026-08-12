FROM golang:1.23-alpine@sha256:2c49857f2295e89b23b28386e57e018a86620a8fede5003900f2d138ba9c4037 AS builder

ARG VERSION=dev

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/oseye-agent ./cmd/oseye-agent && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/oseye-config ./cmd/oseye-config

FROM alpine:3.21@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c

RUN apk add --no-cache ca-certificates && \
    addgroup -S oseye && adduser -S oseye -G oseye

COPY --from=builder /out/oseye-agent /usr/local/bin/oseye-agent
COPY --from=builder /out/oseye-config /usr/local/bin/oseye-config

USER oseye

LABEL org.opencontainers.image.title="oseye-agent" \
      org.opencontainers.image.description="OSEye EDR Agent — eBPF-based Linux telemetry" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/oseye/oseye" \
      org.opencontainers.image.licenses="Apache-2.0"

CMD ["oseye-agent"]

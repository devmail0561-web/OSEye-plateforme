FROM golang:1.23-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o oseye-agent ./cmd/oseye-agent

FROM alpine:3.21
RUN apk add --no-cache ca-certificates

COPY --from=builder /build/oseye-agent /usr/local/bin/oseye-agent

CMD ["oseye-agent"]

FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
COPY web ./web
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/crowdsec-ui .

FROM alpine:3.21

RUN apk add --no-cache ca-certificates wget \
    && mkdir -p /config /crowdsec-data

COPY --from=builder /out/crowdsec-ui /usr/local/bin/crowdsec-ui
COPY contrib/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/crowdsec-ui /usr/local/bin/docker-entrypoint.sh

EXPOSE 8082
VOLUME ["/config"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8082/healthz >/dev/null 2>&1 || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

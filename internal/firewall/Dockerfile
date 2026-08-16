FROM golang:1.25-alpine AS dnspin-builder

# dns-pin is stdlib-only, so this build needs no module downloads.
WORKDIR /src
COPY dnspin/ ./
RUN CGO_ENABLED=0 GO111MODULE=off go build -trimpath -o /dns-pin .

FROM alpine:3.20

RUN apk add --no-cache \
    nftables \
    coredns \
    iptables \
    bash \
    bind-tools \
    && rm -rf /var/cache/apk/*

COPY --from=dnspin-builder /dns-pin /usr/local/bin/dns-pin

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

COPY coredns/ /etc/coredns/

ENTRYPOINT ["/entrypoint.sh"]

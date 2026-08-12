FROM alpine:3.20

RUN apk add --no-cache \
    nftables \
    coredns \
    iptables \
    bash \
    && rm -rf /var/cache/apk/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

COPY coredns/ /etc/coredns/

ENTRYPOINT ["/entrypoint.sh"]

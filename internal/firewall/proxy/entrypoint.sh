#!/bin/bash
set -e

# Proxy mode — nginx reverse proxy
if [ -z "${AGENT_IP:-}" ] || [ -z "${AGENT_PORT:-}" ]; then
    echo "ERROR: AGENT_IP and AGENT_PORT env vars are required" >&2
    exit 1
fi

AGENT_PORT_NUM=$(echo "$AGENT_PORT" | sed 's|/tcp||')

# Generate nginx config
cat > /etc/nginx/nginx.conf <<NGINX_EOF
worker_processes 1;
daemon off;

events {
    worker_connections 1024;
}

http {
    access_log /dev/stdout;
    error_log /dev/stderr;

    server {
        listen ${AGENT_PORT_NUM};

        location / {
            proxy_pass http://${AGENT_IP}:${AGENT_PORT_NUM};
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_read_timeout 86400s;
            proxy_send_timeout 86400s;
        }
    }
}
NGINX_EOF

echo "Proxy ready. Forwarding port ${AGENT_PORT_NUM} → ${AGENT_IP}:${AGENT_PORT_NUM}"
exec nginx

FROM caddy:2-alpine

COPY Caddyfile /etc/caddy/Caddyfile

COPY certs/app.localhost.pem /etc/ssl/local/app.localhost.pem
COPY certs/app.localhost-key.pem /etc/ssl/local/app.localhost-key.pem

EXPOSE 443
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]


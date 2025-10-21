#!/bin/sh

docker run --rm \
  --name crs-caddy \
  --network crs-net \
  -p 443:443 \
  crs-caddy:latest

#!/bin/sh

docker run -it \
  --rm \
  --init \
  --name crs-proxy \
  --network crs-net \
  -e PGHOST=postgres-instance \
  -e PGPORT=5432 \
  -e PGUSER=postgres \
  -e PGDATABASE=postgres \
  -p 8000:8000 \
  crs-proxy:latest 'abc123'

FROM python:3.11-slim

# psycopg runtime lib
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libpq5 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY proxy.py protocol.py ./

EXPOSE 6000

# Keep ENTRYPOINT so we can pass DB password as an argument:
# docker run ... crs-proxy:latest <PGPASSWORD>
ENTRYPOINT ["python", "proxy.py"]


FROM python:3.11-slim

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libpq5 ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY protocol.py /app/protocol.py
COPY proxy.py /app/proxy.py
COPY web /app/web

EXPOSE 8000

ENTRYPOINT ["python", "proxy.py"]

FROM python:3.11-slim

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libpq5 ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY python_web_server/common.py /app/common.py
COPY python_web_server/proxy.py /app/proxy.py
COPY web_client /app/web_client

EXPOSE 8000

ENTRYPOINT ["python", "proxy.py"]

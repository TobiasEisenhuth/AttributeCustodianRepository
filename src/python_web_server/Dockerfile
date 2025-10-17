FROM python:3.11-slim

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libpq5 ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY src/python_web_server/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY src/python_web_server/protocol.py /app/protocol.py
COPY src/python_web_server/proxy.py    /app/proxy.py
COPY src/web_client /app/web_client

EXPOSE 8000

ENTRYPOINT ["python", "proxy.py"]

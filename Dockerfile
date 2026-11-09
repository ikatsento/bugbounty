FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl dnsutils git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY bounty_recon.py .
RUN chmod +x bounty_recon.py

ENTRYPOINT ["python3", "bounty_recon.py"]

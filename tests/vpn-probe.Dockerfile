FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    openconnect vpnc-scripts iproute2 iptables python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY tests/vpn-probe.py /probe.py
ENTRYPOINT ["python3", "/probe.py"]

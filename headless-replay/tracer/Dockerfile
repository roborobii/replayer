# Unicorn-based code-path tracer for DXRender.exe.
#
# Pure Python + Unicorn — no x86 emulation by the host required.
# Runs natively on arm64 (Apple Silicon) and amd64 alike.
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends binutils ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Pin versions for reproducibility. unicorn 2.x has native arm64 wheels.
RUN pip install --no-cache-dir \
        unicorn==2.1.1 \
        capstone==5.0.3 \
        pefile==2024.8.26

WORKDIR /app
COPY tracer.py /app/tracer.py
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]

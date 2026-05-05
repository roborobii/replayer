FROM python:3.12-slim

WORKDIR /app

COPY v2_server.py cipher.py spawn_parser.py entrypoint.sh ./
RUN chmod +x /app/entrypoint.sh

EXPOSE 1818 1819 18123 18124

ENTRYPOINT ["/app/entrypoint.sh"]

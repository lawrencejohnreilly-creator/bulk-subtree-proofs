FROM python:3.12-alpine

WORKDIR /site
COPY index.html .

# Railway injects PORT. Bind 0.0.0.0 or the health check will not reach us.
CMD ["sh", "-c", "python -m http.server ${PORT:-8080} --bind 0.0.0.0"]

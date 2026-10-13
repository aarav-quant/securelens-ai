FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

# Non-root user with a writable home (Semgrep keeps a small cache in ~/.semgrep).
RUN useradd --create-home --uid 10001 app
COPY app ./app
COPY rules ./rules
COPY tests ./tests
USER app

# Fail the build if a scanner is not actually usable inside the image.
RUN bandit --version >/dev/null && semgrep --version >/dev/null

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]

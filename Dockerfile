FROM python:3.13.15-alpine3.24 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    CSAGE_DATA_DIR=/data

WORKDIR /app

# Keep the runtime OS fully patched and explicitly require a SQLite build
# newer than the FTS5 fixes reported by AWS Inspector. Alpine uses musl,
# so the Debian glibc finding is removed, and the minimal image does not
# carry the Perl packages responsible for the reported Perl CVEs.
RUN apk upgrade --no-cache \
    && apk add --no-cache \
        ca-certificates \
        'sqlite-libs>=3.53.4-r0' \
    && update-ca-certificates \
    && addgroup -S csage \
    && adduser -S -D -H -G csage csage

COPY requirements.txt /app/requirements.txt
RUN python -m pip install --upgrade pip \
    && python -m pip install -r /app/requirements.txt

COPY . /app
RUN mkdir -p /data \
    && python manage.py collectstatic --noinput \
    && chown -R csage:csage /app /data

USER csage
EXPOSE 8000
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz/', timeout=3)" || exit 1

CMD ["sh", "-c", "gunicorn csage.wsgi:application --bind 0.0.0.0:8000 --workers ${GUNICORN_WORKERS:-3} --threads ${GUNICORN_THREADS:-4} --timeout ${GUNICORN_TIMEOUT:-300} --access-logfile - --error-logfile -"]

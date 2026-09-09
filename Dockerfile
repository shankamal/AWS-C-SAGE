FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    CSAGE_DATA_DIR=/data

WORKDIR /app

RUN addgroup --system csage && adduser --system --ingroup csage csage

COPY requirements.txt /app/requirements.txt
RUN pip install --upgrade pip && pip install -r /app/requirements.txt

COPY . /app
RUN mkdir -p /data \
    && python manage.py collectstatic --noinput \
    && chown -R csage:csage /app /data

USER csage
EXPOSE 8000
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz/', timeout=3)" || exit 1

CMD ["sh", "-c", "gunicorn csage.wsgi:application --bind 0.0.0.0:8000 --workers ${GUNICORN_WORKERS:-3} --threads ${GUNICORN_THREADS:-4} --timeout ${GUNICORN_TIMEOUT:-300} --access-logfile - --error-logfile -"]

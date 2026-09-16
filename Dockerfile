FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY itds/ ./itds/
COPY rules/ ./rules/
COPY pyproject.toml .

RUN useradd --create-home --shell /bin/bash sentry \
    && mkdir -p /app/data && chown -R sentry:sentry /app
USER sentry

ENV ITDS_DB_PATH=/app/data/itds.db
EXPOSE 8000

CMD ["uvicorn", "itds.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

# syntax=docker/dockerfile:1.7
FROM ghcr.io/astral-sh/uv:0.12.5 AS uv

FROM python:3.12-slim-bookworm AS base
ENV PYTHONUNBUFFERED=1
ENV UV_PROJECT_ENVIRONMENT=/opt/venv
ENV PATH=/opt/venv/bin:$PATH
WORKDIR /app

RUN groupadd --system --gid 1001 toy \
  && useradd --system --uid 1001 --gid toy --home-dir /app toy

COPY --from=uv /uv /uvx /bin/
COPY backend/pyproject.toml backend/uv.lock ./

FROM base AS api
RUN uv sync --frozen --no-dev
COPY backend/app ./app
COPY backend/alembic.ini ./alembic.ini
COPY backend/migrations ./migrations
USER toy
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

FROM base AS worker
RUN uv sync --frozen --no-dev --group analyzer
COPY backend/app ./app
COPY analyzer /analyzer
RUN chmod +x /analyzer/scripts/verify-languages.sh \
  && mkdir -p /work /data/sources \
  && chown -R toy:toy /work /data/sources
USER toy
CMD ["python", "-m", "app.worker"]

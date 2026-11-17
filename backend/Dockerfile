FROM python:3.13-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends fonts-dejavu-core ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY backend/requirements.txt backend/constraints-tested.txt ./
RUN pip install --no-cache-dir -c constraints-tested.txt -r requirements.txt
RUN useradd -u 10001 -M bae
COPY backend/app ./app
COPY backend/migrations ./migrations
COPY backend/alembic.ini ./
COPY contracts ./contracts
RUN chmod -R a+rX /app
USER 10001
CMD ["uvicorn","app.api:app","--host","0.0.0.0","--port","8000","--no-access-log","--log-level","warning"]

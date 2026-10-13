# Optional container build (UNTESTED in this release: Docker was not available on the build machine).
FROM node:20-bookworm-slim AS ui
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    THREATREADY_ENV=production \
    THREATREADY_DATABASE_URL=sqlite:////data/threatready.db \
    THREATREADY_LAB_DATA_DIR=/data/labs \
    THREATREADY_FRONTEND_DIST=/app/frontend/dist
WORKDIR /app/backend
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ ./
COPY --from=ui /ui/dist /app/frontend/dist
RUN useradd --create-home threatready && mkdir -p /data && chown threatready /data
USER threatready
VOLUME ["/data"]
EXPOSE 8000
CMD ["sh", "-c", "python -m app.cli init-db && uvicorn app.main:app --host 0.0.0.0 --port 8000"]

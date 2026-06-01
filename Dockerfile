# Stage 1: Kompilasi Tailwind CSS
FROM node:20-alpine AS css-builder
WORKDIR /build

# Copy file konfigurasi untuk Tailwind CSS
COPY package.json tailwind.config.js input.css ./
# Copy folder templates untuk proses scanning class Tailwind yang terpakai
COPY app/templates ./app/templates

# Install dependensi Node dan compile CSS
RUN npm install
RUN npm run build:css

# Stage 2: Runtime Aplikasi Python FastAPI
FROM python:3.13-slim AS runner

# Salin binary uv dari official image Astral uv ke runner image
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Set working directory
WORKDIR /app

# Hindari buffering output python di logs Docker
ENV PYTHONUNBUFFERED=1
ENV APP_ENV=production

# Copy manifest files
COPY pyproject.toml uv.lock ./

# Install python dependencies (tanpa source code dulu untuk optimasi cache layer Docker)
RUN uv sync --frozen --no-cache --no-install-project

# Copy static assets & templates
COPY app/templates ./app/templates
COPY app/static/js ./app/static/js

# Salin compiled CSS hasil kompilasi dari Stage 1
COPY --from=css-builder /build/app/static/css/tailwind.min.css ./app/static/css/

# Copy python app source code
COPY app ./app

# Install project package
RUN uv sync --frozen --no-cache

# Expose port untuk server FastAPI
EXPOSE 8000

# Command untuk menjalankan Uvicorn via uv run
CMD ["uv", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

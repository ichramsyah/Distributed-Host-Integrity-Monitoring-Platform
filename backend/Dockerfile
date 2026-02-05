# ⚠ DISCLAIMER:
# This Dockerfile is intended for portfolio and showcase purposes only.
# It represents a simplified container setup for demonstration.
# Production images may include additional security hardening.

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "backend.wsgi:application"]
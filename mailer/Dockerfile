FROM python:3.11-slim-bookworm

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libpq-dev \
    libssl-dev \
    libffi-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN python3.11 -m pip install --upgrade pip
RUN python3.11 -m pip install --upgrade setuptools 
RUN python3.11 -m pip install flask python-dotenv
RUN python3.11 -m pip install uwsgi

COPY mail.py .

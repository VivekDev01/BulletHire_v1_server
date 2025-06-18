FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
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
RUN python3.11 -m pip install pyyaml
RUN python3.11 -m pip install jinja2
RUN python3.11 -m pip install pymongo dnspython
RUN python3.11 -m pip install werkzeug
RUN python3.11 -m pip install --ignore-installed flask flask_session flask-socketio flask_cors flask-compress uwsgi
RUN python3.11 -m pip install bcrypt
RUN python3.11 -m pip install pyjwt pem pyjwt[crypto]

COPY ./src ./src
WORKDIR /src/

RUN ln -s /usr/bin/python3.11 /usr/bin/python

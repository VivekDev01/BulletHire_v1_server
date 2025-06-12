FROM python:3.10-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV APP_NAME="BulletHire"
ENV USER=root
ENV HOME=/root

USER root

ENV PYTHONPATH=/home/${USERNAME}/$APP_NAME:/home/${USERNAME}

RUN apt-get -y update
RUN apt-get  install -y software-properties-common
RUN add-apt-repository ppa:deadsnakes/ppa

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
	build-essential \
        curl \
        gcc \
        g++ \
        python3.10-dev \
        python3-pip \
        python3.10 \
        libopenmpi-dev \
        libsm6 \
        libxext6 \
        libxrender-dev \
        libglib2.0-0

RUN python3.10 -m pip install --upgrade pip
RUN python3.10 -m pip install --upgrade setuptools 
RUN python3.10 -m pip install pyyaml
RUN python3.10 -m pip install jinja2
RUN python3.10 -m pip install pymongo dnspython
RUN python3.10 -m pip install werkzeug
RUN python3.10 -m pip install flask==3.1.0 flask_session flask-socketio flask_cors flask-compress uwsgi
RUN python3.10 -m pip install bcrypt
RUN python3.10 -m pip install pyjwt pem pyjwt[crypto]

COPY ./src ./src
WORKDIR /src/

RUN ln -s /usr/bin/python3.10 /usr/bin/python

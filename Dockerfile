FROM python:3.11-slim-bookworm

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
RUN python3.11 -m pip install jinja2
RUN python3.11 -m pip install dnspython
RUN python3.11 -m pip install --ignore-installed flask flask_session flask-socketio flask_cors flask-compress uwsgi
RUN python3.11 -m pip install bcrypt
RUN python3.11 -m pip install pyjwt pem pyjwt[crypto]
RUN python3.11 -m pip install charset-normalizer==3.4.1
RUN python3.11 -m pip install fastapi==0.115.12
RUN python3.11 -m pip install google-api-core==2.24.2
RUN python3.11 -m pip install google-api-python-client==2.170.0
RUN python3.11 -m pip install google-auth==2.40.2
RUN python3.11 -m pip install google-auth-httplib2==0.2.0
RUN python3.11 -m pip install google-auth-oauthlib==1.2.2
RUN python3.11 -m pip install google-cloud-core==2.4.3
RUN python3.11 -m pip install google-search-results==2.4.2
RUN python3.11 -m pip install httpcore==1.0.7
RUN python3.11 -m pip install httplib2==0.22.0
RUN python3.11 -m pip install httpx==0.28.1
RUN python3.11 -m pip install httpx-sse==0.4.0
RUN python3.11 -m pip install huggingface-hub==0.29.1
RUN python3.11 -m pip install langchain==0.3.25
RUN python3.11 -m pip install langchain-community==0.3.24
RUN python3.11 -m pip install langchain-core==0.3.63
RUN python3.11 -m pip install langchain-experimental==0.3.4
RUN python3.11 -m pip install langchain-google-community==2.0.7
RUN python3.11 -m pip install langchain-openai==0.3.7
RUN python3.11 -m pip install langchain-text-splitters==0.3.8
RUN python3.11 -m pip install langgraph-prebuilt==0.2.2
RUN python3.11 -m pip install langgraph-sdk==0.1.70
RUN python3.11 -m pip install numpy==2.2.3
RUN python3.11 -m pip install oauthlib==3.2.2
RUN python3.11 -m pip install openai==1.64.0
RUN python3.11 -m pip install ormsgpack==1.10.0
RUN python3.11 -m pip install packaging==24.2
RUN python3.11 -m pip install pandas==2.2.3
RUN python3.11 -m pip install pydantic==2.10.6
RUN python3.11 -m pip install pydantic-settings==2.8.1
RUN python3.11 -m pip install pypdf==5.4.0
RUN python3.11 -m pip install python-dateutil==2.9.0.post0
RUN python3.11 -m pip install python-dotenv==1.0.1
RUN python3.11 -m pip install python-multipart==0.0.20
RUN python3.11 -m pip install pytz==2025.1
RUN python3.11 -m pip install PyYAML==6.0.2
RUN python3.11 -m pip install regex==2024.11.6
RUN python3.11 -m pip install requests==2.32.3
RUN python3.11 -m pip install requests-oauthlib==2.0.0
RUN python3.11 -m pip install rsa==4.9.1
RUN python3.11 -m pip install scikit-learn==1.6.1
RUN python3.11 -m pip install scipy==1.15.2
RUN python3.11 -m pip install sentence-transformers==3.4.1
RUN python3.11 -m pip install starlette==0.46.2
RUN python3.11 -m pip install transformers==4.49.0
RUN python3.11 -m pip install uritemplate==4.1.1
RUN python3.11 -m pip install urllib3==2.3.0
RUN python3.11 -m pip install uvicorn==0.34.3
RUN python3.11 -m pip install Werkzeug==3.1.3
RUN python3.11 -m pip install pymongo==4.13.2
RUN python3.11 -m pip install torch==2.1.2
RUN python3.11 -m pip install torchvision==0.16.2
RUN python3.11 -m pip install torchaudio==2.1.2
RUN python3.11 -m pip install authlib==1.6.3

COPY ./src ./src
WORKDIR /src/

# RUN ln -s /usr/bin/python3.11 /usr/bin/python  #-- for flask
# CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]    # -- for fastapi


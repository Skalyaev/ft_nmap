# syntax=docker/dockerfile:1
ARG PYTHON_VERSION=3.11.2
FROM python:${PYTHON_VERSION}-slim

WORKDIR /app

ARG USR=appuser
ARG UID=10001
RUN adduser \
    --disabled-password \
    --gecos '' \
    --home /nonexistent \
    --no-create-home \
    --uid ${UID} \
    ${USR}

RUN --mount=type=cache,target=/root/.cache/apt \
    --mount=type=bind,source=requirement.apt,target=requirement.apt \
    apt-get update \
    && apt-get install -y $(cat requirement.apt) \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN --mount=type=cache,target=/root/.cache/pip \
    --mount=type=bind,source=requirement.pip,target=requirement.pip \
    python -m pip install -r requirement.pip

ARG HOST_BACK
ARG PORT_BACK

COPY app.py .
CMD uvicorn 'app:app' --host=${HOST_BACK} --port=${PORT_BACK}

# syntax=docker/dockerfile:1
ARG NODE_VERSION=18.19.0
FROM node:${NODE_VERSION}-alpine

WORKDIR /app
COPY index.html .

RUN --mount=type=cache,target=/root/.cache/npm \
    npm install -g http-server

ARG PORT_FRONT

USER node
CMD http-server --port ${PORT_FRONT}

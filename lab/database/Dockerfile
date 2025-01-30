# syntax=docker/dockerfile:1
ARG POSTGRES_VERSION=17.2
FROM postgres:${POSTGRES_VERSION}-alpine

RUN apk add --no-cache musl-locales

COPY init.sh /docker-entrypoint-initdb.d/.
RUN chmod 755 /docker-entrypoint-initdb.d/init.sh

# USER postgres
# Run as root on database initialization
USER root

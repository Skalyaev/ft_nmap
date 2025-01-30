# syntax=docker/dockerfile:1
ARG NGINX_VERSION=1.27.2
FROM nginx:${NGINX_VERSION}-alpine

WORKDIR /etc/nginx

COPY nginx.conf .
COPY template/default.conf.template templates/.

COPY ssl/crt/dev.* ssl/crt/.
COPY ssl/ssl.conf ssl/.
COPY ssl/dhparams.pem ssl/.

RUN chown -R nginx:nginx .
USER nginx

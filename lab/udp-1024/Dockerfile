ARG PYTHON_VERSION=3.12
FROM python:${PYTHON_VERSION}-alpine

COPY server.py /app/server.py

WORKDIR /app
CMD ["python", "/app/server.py"]

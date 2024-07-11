FROM python:3.12.4-slim as base
FROM base as builder
RUN mkdir /install
WORKDIR /install
COPY install/requirements.txt /requirements.txt
RUN pip3 install --prefix=/install --require-hashes -r /requirements.txt
FROM base
COPY --from=builder /install /usr/local
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY oxo.yaml /app/agent/oxo.yaml
WORKDIR /app
CMD ["python3", "/app/agent/ping_agent.py"]
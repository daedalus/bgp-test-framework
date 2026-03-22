FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    curl \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

COPY . /app
RUN pip install --no-cache-dir -e .

RUN chmod +x /app/examples/docker/run_tests.sh

CMD ["/app/examples/docker/run_tests.sh"]

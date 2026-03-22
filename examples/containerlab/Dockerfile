# BGP Test Framework Test Container
# Builds a container with BGP test framework for use with containerlab

FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install the BGP test framework
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -e .

# Default command runs tests against localhost
CMD ["bgp-test", "--target", "127.0.0.1", "--as-number", "65001", "-v"]

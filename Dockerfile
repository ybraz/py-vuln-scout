# Dockerfile for py-vuln-scout
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
COPY examples/ ./examples/

# Install Python dependencies
RUN pip install --no-cache-dir -e .

# Create cache directory
RUN mkdir -p .pvs_cache

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Default command
ENTRYPOINT ["pvs"]
CMD ["--help"]

# Usage:
# Build: docker build -t py-vuln-scout .
# Run:   docker run --rm -v $(pwd):/workspace py-vuln-scout analyze /workspace/myfile.py
#
# Note: For LLM features, Ollama must be accessible from the container.
# Use --network=host on Linux or specify Ollama host with --model-base-url

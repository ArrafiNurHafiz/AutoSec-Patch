FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    patch \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN groupadd -r appgroup && useradd -r -g appgroup appuser

# Copy configuration files
COPY pyproject.toml README.md LICENSE ./

# Copy source code and templates
COPY autosec/ ./autosec/
COPY climatetrust/ ./climatetrust/
COPY templates/ ./templates/
COPY examples/ ./examples/

# Install python dependencies
RUN pip install --no-cache-dir -e .

# Switch to non-root user for better security
USER appuser

ENTRYPOINT ["python3", "-m", "autosec.cli"]
CMD ["--help"]

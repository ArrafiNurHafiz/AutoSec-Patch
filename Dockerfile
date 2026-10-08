FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    patch \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md LICENSE ./
COPY autosec/ ./autosec/
COPY examples/ ./examples/

RUN pip install --no-cache-dir -e .

ENTRYPOINT ["python3", "-m", "autosec.cli"]
CMD ["--help"]

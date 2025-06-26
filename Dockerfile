FROM python:3.11-slim

# Install eBPF build tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        clang llvm bpftool linux-headers-amd64 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app
RUN pip install .

CMD ["python", "examples/echo.py"]

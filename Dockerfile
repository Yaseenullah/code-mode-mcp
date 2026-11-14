
# --------------------------------------------------
# 1. Base image: Rust + Debian Linux
# --------------------------------------------------
FROM rust:1-bookworm

# --------------------------------------------------
# 2. Install system dependencies and Node.js
# --------------------------------------------------
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    build-essential \
    pkg-config \
    libssl-dev \
    curl \
    ca-certificates \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# --------------------------------------------------
# 3. Set working directory
# --------------------------------------------------
WORKDIR /app

# --------------------------------------------------
# 4. Install Python dependencies
# --------------------------------------------------
COPY server/requirements.txt ./server/requirements.txt

RUN python3 -m venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --no-cache-dir \
    -r server/requirements.txt

# --------------------------------------------------
# 5. Install Node.js dependencies
# --------------------------------------------------
COPY executor/package.json executor/package-lock.json ./executor/

WORKDIR /app/executor

RUN npm ci

# --------------------------------------------------
# 6. Copy Rust source and compile supervisor
# --------------------------------------------------
WORKDIR /app

COPY supervisor/ ./supervisor/

RUN cargo build --release --manifest-path supervisor/Cargo.toml

# --------------------------------------------------
# 7. Copy complete application source
# --------------------------------------------------
COPY server/ ./server/
COPY executor/ ./executor/

# --------------------------------------------------
# 8. Runtime configuration
# --------------------------------------------------
ENV MCP_TRANSPORT=streamable-http
ENV MCP_HOST=0.0.0.0
ENV PYTHONUNBUFFERED=1

# --------------------------------------------------
# 9. Start Python MCP server
# --------------------------------------------------
CMD ["python3", "server/server.py"]

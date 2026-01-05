FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    openjdk-11-jdk \
    openjdk-11-jdk-headless \
    python3.11 \
    python3-pip \
    nodejs \
    npm \
    git \
    curl \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Copy all source
COPY . .

# Build all components
RUN cd ghidra-plugin && chmod +x gradlew && ./gradlew build

RUN cd python-mcp && pip install -e .

RUN cd web-dashboard && npm install && npm run build

EXPOSE 8000 8001 8002 3000 8100

CMD ["bash"]

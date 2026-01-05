# Installation & Setup Guide

## System Requirements

### Minimum
- **OS**: Linux, macOS, or Windows (WSL2)
- **CPU**: 2 cores @ 2GHz
- **RAM**: 4GB
- **Disk**: 5GB (for Ghidra + tools)
- **Java**: JDK 11+
- **Python**: 3.9+
- **Node.js**: 18+ (for dashboard)

### Recommended
- **CPU**: 4+ cores @ 3GHz+
- **RAM**: 8GB+
- **Disk**: 20GB+ (for large binary analysis)
- **Ghidra**: 11.0+

### Optional
- **Docker**: For containerized deployment
- **PostgreSQL**: For analysis caching
- **Redis**: For session storage

---

## Installation Methods

### Method 1: Docker Compose (Recommended)

**Easiest setup** - all components in containers.

#### Prerequisites
- Docker 20.10+
- Docker Compose 2.0+

#### Steps

```bash
# Clone repository
git clone https://github.com/yourusername/GhidraInsight.git
cd GhidraInsight

# Start services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

**Access**:
- Dashboard: http://localhost:3000
- API: http://localhost:8000
- Docs: http://localhost:3001

**Stop**:
```bash
docker-compose down
```

---

### Method 2: Manual Installation

#### 1. Install Ghidra

```bash
# Download from https://ghidra-sre.org/
export GHIDRA_INSTALL_DIR=/opt/ghidra-11.0
mkdir -p $GHIDRA_INSTALL_DIR

# Extract
unzip ghidra_11.0_PUBLIC_*.zip -d $GHIDRA_INSTALL_DIR

# Test installation
$GHIDRA_INSTALL_DIR/ghidraRun
```

#### 2. Build & Install Java Plugin

```bash
cd ghidra-plugin

# Ensure GHIDRA_INSTALL_DIR is set
export GHIDRA_INSTALL_DIR=/opt/ghidra-11.0

# Build
./gradlew build

# Install to Ghidra
mkdir -p $GHIDRA_INSTALL_DIR/Extensions/Ghidra/plugins
cp build/libs/GhidraInsight-*.jar \
   $GHIDRA_INSTALL_DIR/Extensions/Ghidra/plugins/

# Verify
ls -la $GHIDRA_INSTALL_DIR/Extensions/Ghidra/plugins/
```

#### 3. Set Up Python MCP Server

```bash
cd python-mcp

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install package with dev dependencies
pip install -e ".[dev]"

# Test installation
python -c "import ghidrainsight; print(ghidrainsight.__version__)"

# Run server
ghidrainsight-server --host 0.0.0.0 --port 8000
```

#### 4. Set Up Web Dashboard

```bash
cd web-dashboard

# Install dependencies
npm install

# Development server
npm run dev

# Production build
npm run build
```

---

### Method 3: From Source (Development)

```bash
# Clone with development dependencies
git clone --depth 1 https://github.com/yourusername/GhidraInsight.git
cd GhidraInsight

# Install all development tools
make setup  # or: ./scripts/setup.sh

# Run tests
make test

# Build everything
make build

# Start services
make start
```

---

## Configuration

### Environment Variables

Create `.env` file in project root:

```bash
# Server
GHIDRA_INSTALL_DIR=/opt/ghidra-11.0
SERVER_HOST=0.0.0.0
SERVER_PORT=8000
SERVER_LOG_LEVEL=INFO

# Authentication
JWT_SECRET=your-super-secret-key-at-least-32-chars
JWT_ALGORITHM=HS256
API_KEY=your-api-key-here

# Security
RATE_LIMIT=60
CORS_ORIGINS=http://localhost:3000,http://localhost:5173

# Database (optional)
DATABASE_URL=postgresql://user:pass@localhost/ghidrainsight
REDIS_URL=redis://localhost:6379

# LLM Integration
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...

# Telemetry
TELEMETRY_ENABLED=false
TELEMETRY_ENDPOINT=https://telemetry.ghidrainsight.dev
```

### Configuration File (YAML)

`config.yaml`:

```yaml
server:
  host: 0.0.0.0
  port: 8000
  workers: 4
  
auth:
  enabled: true
  provider: jwt
  secret: ${JWT_SECRET}
  
security:
  rate_limit:
    requests_per_minute: 60
    burst_size: 10
  
  cors:
    enabled: true
    allowed_origins:
      - http://localhost:3000
      - https://yourdomain.com
  
  max_file_size_gb: 1

analysis:
  timeout_seconds: 300
  parallel_jobs: 2
  
logging:
  level: INFO
  format: json
  file: /var/log/ghidrainsight/server.log
```

Start with config:

```bash
ghidrainsight-server --config config.yaml
```

---

## Post-Installation Setup

### 1. Generate JWT Secret

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Update `.env`:
```bash
JWT_SECRET=<generated-secret>
```

### 2. Test Installation

```bash
# Test Java plugin
curl http://localhost:8000/api/status

# Test Python server
curl -X GET http://localhost:8000/api/status

# Test web dashboard
curl http://localhost:3000
```

### 3. Upload First Binary

```bash
# Using CLI
ghidrainsight analyze --file example.elf --features crypto,vulnerabilities

# Using API
curl -X POST http://localhost:8000/api/analyze \
  -F "file=@example.elf" \
  -H "X-API-Key: your-api-key"
```

---

## Troubleshooting

### Port Already in Use

```bash
# Find process
lsof -i :8000

# Kill process
kill -9 <PID>

# Or use different port
ghidrainsight-server --port 8001
```

### Ghidra Plugin Not Loading

```bash
# Check plugin directory
ls $GHIDRA_INSTALL_DIR/Extensions/Ghidra/plugins/

# Check Ghidra logs
tail -f $GHIDRA_INSTALL_DIR/logs/ghidra.log

# Restart Ghidra
$GHIDRA_INSTALL_DIR/ghidraRun &
```

### Memory Issues

```bash
# Increase JVM memory
export JAVA_OPTS="-Xmx8g"
ghidrainsight-server

# Or in docker-compose.yml:
environment:
  - JAVA_OPTS=-Xmx8g
```

### WebSocket Connection Fails

1. Check firewall allows port 8001
2. Verify `CORS_ORIGINS` includes client URL
3. Check logs: `docker-compose logs python-mcp`
4. Try HTTP polling as fallback

### Out of Memory

- Reduce file size or split analysis
- Close other applications
- Check for memory leaks: `jmap -heap <pid>`
- Increase system swap

---

## Verification Checklist

After installation:

- [ ] `curl http://localhost:8000/api/status` returns 200
- [ ] `curl http://localhost:3000` loads dashboard
- [ ] Can upload a binary file
- [ ] Analysis starts and completes
- [ ] Results display in dashboard
- [ ] No errors in logs

---

## Next Steps

1. **Configure Authentication**: Set JWT_SECRET and API_KEY
2. **Enable CORS**: Configure allowed origins
3. **Integrate LLM**: Add OpenAI/Anthropic keys for AI features
4. **Load Data**: Upload test binaries
5. **Review Logs**: Check for warnings/errors

---

## Uninstallation

### Docker Compose

```bash
docker-compose down -v  # -v removes volumes
```

### Manual

```bash
# Stop services
pkill -f ghidrainsight-server
pkill -f "npm run dev"

# Remove plugin from Ghidra
rm $GHIDRA_INSTALL_DIR/Extensions/Ghidra/plugins/GhidraInsight-*.jar

# Remove Python package
pip uninstall ghidrainsight

# Remove source
rm -rf ~/GhidraInsight
```

---

## Getting Help

- **Issues**: https://github.com/yourusername/GhidraInsight/issues
- **Discussions**: https://github.com/yourusername/GhidraInsight/discussions
- **Email**: support@ghidrainsight.dev
- **Slack**: ghidrainsight.slack.com

---

**Successfully installed GhidraInsight? Great! Start exploring binaries.** 🔍

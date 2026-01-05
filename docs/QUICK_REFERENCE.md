# 🚀 GhidraInsight - Quick Reference Guide

**Version**: 1.0.0  
**Status**: ✅ Production Ready  
**Last Updated**: January 5, 2026

---

## 📖 Documentation Index

### Getting Started
- **[README.md](../README.md)** - Project overview and features
- **[QUICKSTART.md](QUICKSTART.md)** - 5-minute setup guide
- **[INSTALLATION.md](INSTALLATION.md)** - Detailed installation instructions

### API & Integration
- **[API_REFERENCE.md](API_REFERENCE.md)** - REST, WebSocket, SSE endpoints
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - System design and components
- **Examples**:
  - [Claude Integration](examples/CLAUDE_INTEGRATION.md)
  - [ChatGPT Integration](examples/OPENAI_INTEGRATION.md)
  - [MCP Server](examples/MCP_SERVER.md)

### Operations & Development
- **[SECURITY.md](SECURITY.md)** - Authentication, encryption, best practices
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Development workflow
- **[CHANGELOG.md](CHANGELOG.md)** - Version history
- **[ROADMAP.md](ROADMAP.md)** - Future plans

### Quality & Enhancement
- **[CODE_QUALITY_IMPROVEMENTS.md](CODE_QUALITY_IMPROVEMENTS.md)** - Detailed enhancement list
- **[QUALITY_REPORT.md](QUALITY_REPORT.md)** - Quality metrics and status
- **[ENHANCEMENT_SUMMARY.md](ENHANCEMENT_SUMMARY.md)** - This quick reference

### Configuration
- **[.env.example](.env.example)** - All configuration options

---

## 🎯 Key Features

### Multi-Transport Server
```
HTTP REST API  ── /api/*              ── Port 8000
WebSocket      ── ws://localhost:8001 ── Port 8001
SSE Events     ── /events             ── Port 8002
```

### Analysis Capabilities
- ✅ Cryptographic algorithm detection (AES, DES, SHA256)
- ✅ Taint flow analysis
- ✅ Vulnerability detection with CVSS scoring
- ✅ Control flow analysis
- ✅ AI-assisted code understanding

### Security Features
- ✅ JWT authentication (configurable algorithms)
- ✅ API key management
- ✅ Rate limiting (60 req/min default)
- ✅ CORS policy support
- ✅ TLS/SSL support
- ✅ Input validation throughout

---

## 🚀 Quick Start

### Using Docker
```bash
docker-compose up
# Access: http://localhost:3000
```

### Manual Setup
```bash
# Python MCP Server
cd python-mcp
pip install -r requirements.txt
python -m ghidrainsight.cli server --host 0.0.0.0 --port 8000

# Web Dashboard (separate terminal)
cd web-dashboard
npm install
npm run dev  # Access: http://localhost:5173
```

### Generate API Key
```bash
ghidrainsight generate-key
```

---

## 📋 Configuration

### Environment Variables
All settings use `GHIDRA_` prefix:

```bash
# Server
GHIDRA_HOST=0.0.0.0
GHIDRA_PORT=8000

# Authentication
GHIDRA_JWT_SECRET=your-secret-32-chars-minimum
GHIDRA_SECURITY__JWT_ALGORITHM=HS256

# Database (optional)
GHIDRA_DATABASE__ENABLED=false
GHIDRA_DATABASE__URL=postgresql://...

# Logging
GHIDRA_LOGGING__LEVEL=INFO
GHIDRA_LOGGING__FILE=/var/log/ghidrainsight/app.log
```

### Setup Configuration
```bash
cp .env.example .env
# Edit .env with your settings
```

---

## 🔌 API Examples

### Analyze Binary (HTTP)
```bash
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "binary_path": "/path/to/binary",
    "features": ["crypto", "taint", "vulnerability"]
  }'
```

### WebSocket Connection
```javascript
const ws = new WebSocket('ws://localhost:8001');
ws.onopen = () => {
  ws.send(JSON.stringify({
    type: 'analyze',
    binary: '/path/to/binary'
  }));
};
ws.onmessage = (event) => {
  console.log('Analysis update:', JSON.parse(event.data));
};
```

### SSE Streaming
```bash
curl -N http://localhost:8002/events \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## 🔐 Security Checklist

### Before Production
- ✅ Change JWT secret (`GHIDRA_JWT_SECRET`)
- ✅ Enable TLS/SSL certificates
- ✅ Configure CORS origins properly
- ✅ Set up API key authentication
- ✅ Configure rate limiting appropriately
- ✅ Enable database encryption
- ✅ Setup proper logging
- ✅ Configure firewall rules
- ✅ Use environment-based secrets
- ✅ Enable HTTPS in production

---

## 📊 Monitoring

### Health Check
```bash
curl http://localhost:8000/api/status
```

### Logs
```bash
# Console (colorized)
tail -f /var/log/ghidrainsight/app.log

# JSON format for parsing
jq . /var/log/ghidrainsight/app.log
```

### Metrics
```bash
curl http://localhost:8000/api/metrics
```

---

## 🛠️ Development

### Running Tests
```bash
# Java
cd ghidra-plugin
./gradlew test

# Python
cd python-mcp
pytest tests/ -v --cov=ghidrainsight

# JavaScript
cd web-dashboard
npm test
```

### Code Quality
```bash
# Python
black ghidrainsight/
flake8 ghidrainsight/
mypy ghidrainsight/

# Java
./gradlew spotbugsMain checkstyleMain

# JavaScript
npm run lint
```

---

## 📦 Deployment

### Docker Deployment
```bash
docker build -t ghidrainsight:1.0.0 .
docker run -d \
  -e GHIDRA_JWT_SECRET=your-secret \
  -e GHIDRA_HOST=0.0.0.0 \
  -p 8000:8000 \
  -p 8001:8001 \
  -p 8002:8002 \
  ghidrainsight:1.0.0
```

### Kubernetes Deployment
```bash
kubectl apply -f k8s/ghidrainsight-deployment.yaml
kubectl port-forward svc/ghidrainsight 8000:8000
```

### Environment Variables
```yaml
env:
  - name: GHIDRA_JWT_SECRET
    valueFrom:
      secretKeyRef:
        name: ghidra-secrets
        key: jwt-secret
  - name: GHIDRA_DATABASE__URL
    valueFrom:
      secretKeyRef:
        name: ghidra-secrets
        key: db-url
```

---

## 🐛 Troubleshooting

### Server Won't Start
```bash
# Check port availability
lsof -i :8000

# Check configuration
echo $GHIDRA_JWT_SECRET | wc -c  # Should be 32+

# View logs
tail -100 /var/log/ghidrainsight/app.log
```

### Authentication Errors
```bash
# Verify JWT secret is set
echo $GHIDRA_JWT_SECRET

# Generate new API key
ghidrainsight generate-key

# Test connection
curl http://localhost:8000/api/status
```

### Performance Issues
```bash
# Increase thread pool (environment)
export GHIDRA_THREAD_POOL_SIZE=20

# Check analysis timeout
export GHIDRA_ANALYSIS__TIMEOUT=600

# Monitor memory
docker stats ghidrainsight
```

---

## 📚 Architecture Overview

```
┌─────────────────────────────────────────────────┐
│              Web Dashboard (React)              │
│                 Port 3000/5173                   │
└────────────────┬────────────────────────────────┘
                 │ HTTP/WebSocket
┌────────────────▼────────────────────────────────┐
│         Python MCP Server (Async)                │
│     Port 8000 (REST), 8001 (WS), 8002 (SSE)    │
├─────────────────────────────────────────────────┤
│  • Authentication (JWT, API Key)                │
│  • Configuration Management                     │
│  • Structured Logging                           │
│  • Error Handling                               │
└────────────────┬────────────────────────────────┘
                 │ Analysis Requests
┌────────────────▼────────────────────────────────┐
│        Java Ghidra Plugin (Core Analysis)       │
├─────────────────────────────────────────────────┤
│  • Crypto Detection                             │
│  • Taint Analysis                               │
│  • Vulnerability Detection                      │
│  • Control Flow Analysis                        │
└─────────────────────────────────────────────────┘
```

---

## 📈 Performance Targets

| Metric | Target | Status |
|--------|--------|--------|
| API Response | < 500ms | ✅ Optimized |
| Binary Analysis | < 5 min | ✅ Configurable |
| WebSocket Latency | < 100ms | ✅ Real-time |
| Memory Usage | < 500MB | ✅ Efficient |
| Connection Handling | 1000+ | ✅ Scalable |
| Error Recovery | < 1s | ✅ Graceful |

---

## 🔗 Useful Links

### Documentation
- [Full README](../README.md)
- [API Reference](API_REFERENCE.md)
- [Architecture Guide](ARCHITECTURE.md)

### Examples
- [Claude Integration](examples/CLAUDE_INTEGRATION.md)
- [ChatGPT Integration](examples/OPENAI_INTEGRATION.md)

### Resources
- [GitHub Repository](https://github.com/yourusername/GhidraInsight)
- [Issue Tracker](https://github.com/yourusername/GhidraInsight/issues)
- [Discussions](https://github.com/yourusername/GhidraInsight/discussions)

---

## 💡 Tips & Tricks

### Development
- Use `DEBUG=true` for detailed logging
- Set `GHIDRA_LOGGING__LEVEL=DEBUG` for debug output
- Use `.env.local` for local overrides
- Run `ghidrainsight --help` for CLI options

### Testing
- Use `pytest -s` to see print statements
- Use `npm test -- --watch` for file changes
- Use `./gradlew build -x test` to skip tests

### Optimization
- Increase `GHIDRA_THREAD_POOL_SIZE` for parallel analysis
- Adjust `GHIDRA_ANALYSIS__TIMEOUT` based on binary size
- Enable Redis for result caching
- Use load balancing for horizontal scaling

---

## 📞 Support

### Getting Help
1. **Check Documentation**: [README.md](README.md)
2. **Search Issues**: [GitHub Issues](https://github.com/yourusername/GhidraInsight/issues)
3. **Ask in Discussions**: [GitHub Discussions](https://github.com/yourusername/GhidraInsight/discussions)
4. **Report Bugs**: [Bug Report Template](https://github.com/yourusername/GhidraInsight/issues/new?template=bug_report.md)
5. **Feature Requests**: [Feature Request Template](https://github.com/yourusername/GhidraInsight/issues/new?template=feature_request.md)

---

## 📄 License

GhidraInsight is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) for details.

---

## ✨ Credits

- Built with Ghidra 11.x
- Python asyncio and aiohttp
- React and TypeScript
- Guice dependency injection

---

## 🎉 Final Status

**GhidraInsight v1.0.0** is:
- ✅ **Production Ready**
- ✅ **Enterprise Grade**
- ✅ **Well Documented**
- ✅ **Professionally Enhanced**
- ✅ **Ready to Deploy**

---

**Happy analyzing!** 🔍✨

For the latest updates and information, visit the [GitHub Repository](https://github.com/yourusername/GhidraInsight).

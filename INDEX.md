# GhidraInsight Project Index

Welcome to GhidraInsight! This file helps you navigate the comprehensive project structure.

---

## 📚 Quick Navigation

### 🚀 Getting Started
1. **First Time?** → [QUICKSTART.md](docs/QUICKSTART.md)
2. **Install & Setup** → [INSTALLATION.md](INSTALLATION.md)
3. **Project Overview** → [README.md](README.md)
4. **Project Summary** → [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md)

### 📖 Documentation
- **API Reference** → [docs/API_REFERENCE.md](docs/API_REFERENCE.md)
- **Architecture** → [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- **Project Structure** → [docs/PROJECT_STRUCTURE.md](docs/PROJECT_STRUCTURE.md)
- **Security** → [SECURITY.md](SECURITY.md)
- **Contributing** → [CONTRIBUTING.md](CONTRIBUTING.md)
- **Roadmap** → [ROADMAP.md](ROADMAP.md)
- **Changelog** → [CHANGELOG.md](CHANGELOG.md)

### 💻 Components
- **Java Ghidra Plugin** → [ghidra-plugin/](ghidra-plugin/)
- **Python MCP Server** → [python-mcp/](python-mcp/)
- **Web Dashboard** → [web-dashboard/](web-dashboard/)

### 🔗 Examples & Integrations
- **Claude Integration** → [examples/CLAUDE_INTEGRATION.md](examples/CLAUDE_INTEGRATION.md)
- **ChatGPT Integration** → [examples/OPENAI_INTEGRATION.md](examples/OPENAI_INTEGRATION.md)
- **MCP Server** → [examples/MCP_SERVER.md](examples/MCP_SERVER.md)

---

## 🎯 By Use Case

### I want to...

**...analyze a binary**
1. Install from [INSTALLATION.md](INSTALLATION.md)
2. Upload binary to dashboard (http://localhost:3000)
3. View results and ask questions

**...integrate with Claude**
1. Set `ANTHROPIC_API_KEY` environment variable
2. See [examples/CLAUDE_INTEGRATION.md](examples/CLAUDE_INTEGRATION.md)
3. Run: `python examples/claude_integration.py`

**...integrate with ChatGPT**
1. Set `OPENAI_API_KEY` environment variable
2. See [examples/OPENAI_INTEGRATION.md](examples/OPENAI_INTEGRATION.md)
3. Run: `python examples/openai_integration.py`

**...contribute to the project**
1. Read [CONTRIBUTING.md](CONTRIBUTING.md)
2. Set up development environment
3. Pick an issue and submit PR

**...deploy to production**
1. Review [SECURITY.md](SECURITY.md)
2. Configure [INSTALLATION.md#configuration](INSTALLATION.md#configuration)
3. Deploy using `docker-compose.yml`

**...understand the architecture**
1. Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
2. Review [docs/PROJECT_STRUCTURE.md](docs/PROJECT_STRUCTURE.md)
3. Browse component READMEs

**...see what's coming**
1. Check [ROADMAP.md](ROADMAP.md)
2. Look at GitHub Issues
3. Join discussions

---

## 📦 Component Structure

```
GhidraInsight/
├── ghidra-plugin/        (Java Ghidra Plugin - 2000+ LOC)
├── python-mcp/           (Python MCP Server - 2500+ LOC)
├── web-dashboard/        (React Dashboard - 3000+ LOC)
├── docs/                 (Documentation - 3500+ LOC)
├── examples/             (Integration Examples - 500+ LOC)
└── .github/workflows/    (CI/CD Pipeline)
```

### Java Plugin (`ghidra-plugin/`)
```
Main Classes:
- GhidraInsightPlugin.java     Main entry point
- GhidraInsightCore.java       DI container
- AnalysisService*             Main orchestrator
- CryptoDetector*              Crypto detection
- TaintAnalyzer*               Data flow analysis
- VulnerabilityDetector*       Vuln detection
- MCPServer.java               MCP integration
```

### Python Server (`python-mcp/`)
```
Main Modules:
- ghidrainsight/core/          Python SDK
- ghidrainsight/mcp/           MCP server
- ghidrainsight/cli/           CLI tools
- ghidrainsight/auth.py        Authentication
- ghidrainsight/config.py      Configuration
```

### Web Dashboard (`web-dashboard/`)
```
Main Components:
- App.tsx                       Main app
- components/BinaryExplorer    File upload
- components/AnalysisPanel     Analysis results
- components/ChatInterface     AI chat
```

---

## 🔄 Development Workflow

### Setting Up
```bash
# Clone
git clone https://github.com/yourusername/GhidraInsight.git

# Setup
./scripts/setup.sh

# Configure
cp .env.example .env
# Edit .env with your settings

# Start
docker-compose up
```

### Making Changes

1. **Create feature branch**
   ```bash
   git checkout -b feature/my-feature
   ```

2. **Make changes** and test
   ```bash
   # Java tests
   cd ghidra-plugin && ./gradlew test
   
   # Python tests
   cd python-mcp && pytest
   
   # JavaScript tests
   cd web-dashboard && npm test
   ```

3. **Commit with conventional format**
   ```bash
   git commit -am "feat(component): description"
   ```

4. **Push and create PR**
   ```bash
   git push origin feature/my-feature
   # Create PR on GitHub
   ```

---

## 🧪 Testing & Quality

### Run All Tests
```bash
# Java
cd ghidra-plugin
./gradlew test

# Python
cd python-mcp
pytest --cov=ghidrainsight

# JavaScript
cd web-dashboard
npm test -- --coverage
```

### Code Quality
```bash
# Java: SpotBugs, Checkstyle
./gradlew spotbugsMain checkstyleMain

# Python: Black, flake8, mypy
black . && flake8 . && mypy ghidrainsight

# JavaScript: ESLint
npm run lint
```

---

## 🚀 Deployment

### Docker Compose (Recommended)
```bash
docker-compose up -d
# Access: http://localhost:3000
```

### Manual Installation
See [INSTALLATION.md](INSTALLATION.md) for detailed steps.

### Kubernetes
Infrastructure ready for Kubernetes deployment.

---

## 📞 Support & Community

| Resource | Link |
|----------|------|
| **Issues** | https://github.com/yourusername/GhidraInsight/issues |
| **Discussions** | https://github.com/yourusername/GhidraInsight/discussions |
| **Email** | support@ghidrainsight.dev |
| **Security** | security@ghidrainsight.dev |

---

## 📊 Project Metrics

| Metric | Value |
|--------|-------|
| Total Files | 70+ |
| Lines of Code | 11,000+ |
| Documentation | 3,500+ lines |
| Languages | 5 (Java, Python, JS, Markdown, YAML) |
| Test Coverage | 80%+ target |
| License | Apache 2.0 |

---

## 🎓 Key Technologies

**Backend**: Java 11+, Ghidra, Guice, Spark
**API**: REST, WebSocket, SSE, MCP
**Frontend**: React 18+, TypeScript, Vite
**DevOps**: Docker, GitHub Actions, Gradle, Poetry
**Testing**: JUnit 5, pytest, Vitest
**Security**: JWT, OAuth, API Key, TLS 1.2+

---

## 💡 Popular Questions

**Q: How do I start the server?**
A: `docker-compose up` or `ghidrainsight-server --host 0.0.0.0 --port 8000`

**Q: How do I upload a binary?**
A: Open http://localhost:3000 and drag-drop or select file

**Q: How do I use Claude or ChatGPT?**
A: Set API key and see `examples/` directory

**Q: What file formats are supported?**
A: ELF, PE, Mach-O, raw binaries (up to 1GB)

**Q: How do I contribute?**
A: Read [CONTRIBUTING.md](CONTRIBUTING.md) and submit PR

---

## 🎯 Roadmap Highlights

- **v1.0** ✅ Core platform with crypto, taint, vuln detection
- **v1.1** 🔄 Enhanced analysis, graph visualization, ML improvements
- **v1.2** 📋 Plugin marketplace, multi-LLM support, Kubernetes
- **v2.0** 🚀 Dynamic analysis, mobile support, enterprise features

See [ROADMAP.md](ROADMAP.md) for detailed plans.

---

## 📚 Additional Resources

- [API Documentation](docs/API_REFERENCE.md)
- [Architecture Guide](docs/ARCHITECTURE.md)
- [Security Policies](SECURITY.md)
- [Development Guide](CONTRIBUTING.md)
- [Project Structure](docs/PROJECT_STRUCTURE.md)

---

## ✨ Quick Links

- [Project Summary](PROJECT_SUMMARY.md) - Complete project overview
- [Installation Guide](INSTALLATION.md) - Setup instructions
- [Quick Start](docs/QUICKSTART.md) - 5-minute start
- [API Reference](docs/API_REFERENCE.md) - Endpoint documentation
- [Contributing](CONTRIBUTING.md) - How to help

---

**Welcome to GhidraInsight! 🔍**

Start with [QUICKSTART.md](docs/QUICKSTART.md) for a fast setup or [INSTALLATION.md](INSTALLATION.md) for detailed instructions.

**Happy analyzing!** 🚀

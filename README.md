# GhidraInsight 🔍

> **AI-Powered Binary Analysis Platform**  
> Enterprise-grade reverse engineering with Ghidra, AI-driven insights, and seamless LLM integration.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-brightgreen)](https://www.python.org/)
[![Java 11+](https://img.shields.io/badge/Java-11%2B-brightgreen)](https://www.oracle.com/java/)
[![Docker Ready](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker)](docker-compose.yml)
[![Status: Production](https://img.shields.io/badge/Status-Production-success)]()

---

## ⚡ Quick Start (60 seconds)

### Option 1: Docker (Recommended)
```bash
git clone https://github.com/ismailtsdln/GhidraInsight.git
cd GhidraInsight
docker-compose up -d
open http://localhost:3000  # Dashboard opens automatically
```

### Option 2: Automated Local Setup
```bash
chmod +x scripts/setup.sh
./scripts/setup.sh --mode=all
```

### Option 3: Python-Only (Lightweight)
```bash
pip install ghidrainsight
ghidrainsight analyze --file binary.elf --ai-powered
```

---

## 🚀 Key Features

### 🔬 Advanced Binary Analysis
- **Automated Threat Detection**: Cryptocurrency algorithms, vulnerable patterns, malicious code
- **Taint Analysis**: Complete data flow tracking from source to sink
- **Control Flow Analysis**: Anomaly detection and complexity metrics
- **Symbol Recovery**: Function name inference and type reconstruction

### 🤖 AI-Powered Analysis
- **ChatGPT/Claude Integration**: Ask natural language questions about binaries
- **Automated Vulnerability Scanning**: CVSS scores with AI-powered remediation
- **Pattern Recognition**: ML-based anomaly and weakness detection
- **Intelligent Code Summarization**: Automatic function and module descriptions

### 🌐 Multiple Access Methods
- **Web Dashboard**: Intuitive React UI with real-time analysis
- **Python SDK**: Programmatic access with async support
- **CLI Tools**: Command-line interface for automation
- **MCP Protocol**: Seamless LLM integration (Claude, ChatGPT)
- **REST API**: RESTful endpoints for custom integrations
- **🦙 Local AI**: Ollama and other local models support (NEW)

### 🏗️ Enterprise Architecture
- **Modular Design**: Plug-and-play analysis modules
- **Multi-Transport**: HTTP, WebSocket, Server-Sent Events
- **Scalable**: Horizontal scaling with Docker orchestration
- **Secure**: JWT/OAuth authentication, rate limiting, audit logs
- **Observable**: Comprehensive logging and tracing

---

## 📊 Access Method Comparison

| Use Case | Recommended | Setup Time | Learn Curve |
|----------|-------------|-----------|-------------|
| Interactive analysis + visualization | Web Dashboard | 1 min | Easy |
| CI/CD pipeline integration | Python SDK or CLI | 5 min | Medium |
| LLM assistant integration | MCP Protocol | 10 min | Medium |
| Custom automation scripts | Python SDK | 5 min | Medium |
| Quick one-off analysis | Docker + CLI | 2 min | Easy |

---

## 📋 System Requirements

### Minimum Requirements
| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **RAM** | 4GB | 8GB+ |
| **CPU** | 2 cores | 4+ cores |
| **Disk** | 5GB | 20GB+ |
| **Java** | 11 | 17 LTS |
| **Python** | 3.9 | 3.11+ |
| **Node.js** | 18 | 20 LTS |

### Deployment Options

**Option A: Docker (Recommended for Beginners)**
```bash
✓ Single command setup
✓ No dependency conflicts
✓ Works on Windows, macOS, Linux
✓ Production-ready out of box
Requires: Docker Desktop (download)
```

**Option B: Manual (For Customization)**
```bash
✓ Full control over components
✓ Easier debugging
✓ Smaller resource footprint
Requires: Java 11+, Python 3.9+, Node.js 18+, Ghidra 11+
```

**Option C: Python-Only (Lightweight)**
```bash
✓ No GUI needed
✓ Perfect for servers
✓ Fastest setup
⚠ Requires external Ghidra installation
```

---

## 🛠 Installation Guide

### Method 1️⃣: Docker (Recommended)

**Prerequisites**: [Docker Desktop](https://www.docker.com/products/docker-desktop)

```bash
# 1. Clone and navigate
git clone https://github.com/ismailtsdln/GhidraInsight.git
cd GhidraInsight

# 2. Start all services (one command!)
docker-compose up -d

# 3. Wait for services to start (~30 seconds)
docker-compose logs -f

# 4. Access the platform
echo "✅ Dashboard: http://localhost:3000"
echo "✅ API Server: http://localhost:8000"
echo "✅ WebSocket: ws://localhost:8001"
```

**Stop services**:
```bash
docker-compose down
```

**View logs**:
```bash
docker-compose logs -f ghidra-plugin
docker-compose logs -f python-mcp
docker-compose logs -f web-dashboard
```

**Troubleshooting**:
```bash
# Check service status
docker-compose ps

# Rebuild images
docker-compose build --no-cache

# Remove all containers and start fresh
docker-compose down -v && docker-compose up -d
```

---

### Method 2️⃣: Automated Local Setup (macOS/Linux)

```bash
# Make script executable
chmod +x scripts/setup.sh

# Install everything with one command
./scripts/setup.sh --mode=all --python-version=3.11

# Start the platform
./scripts/startup.sh
```

**For specific components only**:
```bash
./scripts/setup.sh --mode=python-only  # Python MCP server only
./scripts/setup.sh --mode=java         # Java plugin only
./scripts/setup.sh --mode=dashboard    # Dashboard only
```

**Verify installation**:
```bash
ghidrainsight --version
ghidrainsight status
```

---

### Method 3️⃣: Manual Installation

#### Step 1: Java Ghidra Plugin
```bash
cd ghidra-plugin
./gradlew build

# Install to Ghidra
cp build/libs/*.jar $GHIDRA_INSTALL_DIR/Extensions/Ghidra/plugins/

# Restart Ghidra and enable plugin in: Window → Plugin Manager
```

#### Step 2: Python MCP Server
```bash
cd python-mcp
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

pip install -e .
ghidrainsight-server --host 0.0.0.0 --port 8000
```

#### Step 3: Web Dashboard
```bash
cd web-dashboard
npm install
npm run dev  # Opens at http://localhost:5173
```

---

### Method 4️⃣: Python Package Only (PyPI)

```bash
# Install from PyPI (once released)
pip install ghidrainsight

# Verify installation
ghidrainsight --version

# Start server
ghidrainsight serve --port 8000
```

---

## 🎯 Usage Guide

### 1. Web Dashboard (Easiest)

**Perfect for**: Interactive analysis, visualization, learning

Access at **http://localhost:3000** after `docker-compose up`

**Usage Steps**:
1. **Drop a Binary**: Drag file into the upload area or click "Select File"
2. **Auto-Analysis**: System automatically:
   - Detects crypto algorithms
   - Finds vulnerabilities
   - Performs taint analysis
3. **Explore**: Click on functions to see decompilation
4. **Ask AI**: Use chat interface for natural language queries
5. **Export**: Download JSON/PDF reports

**Example AI Questions**:
```
"What does function_0x401000 do?"
"Find all crypto operations"
"Show potential vulnerabilities"
"Analyze data flow from user input"
"Compare this with known malware patterns"
```

---

### 2. Python SDK (For Automation)

**Perfect for**: CI/CD integration, batch processing, custom workflows

```python
from ghidrainsight.client import GhidraInsightClient
import asyncio

async def analyze_binary():
    # Connect to server
    client = GhidraInsightClient("http://localhost:8000")
    
    # Analyze with all features
    results = await client.analyze(
        file_path="/path/to/binary.elf",
        features=["crypto", "taint", "vulnerabilities"],
        ai_powered=True  # Enable AI analysis
    )
    
    # Access results
    print(f"Vulnerabilities: {results.vulnerabilities}")
    print(f"Crypto: {results.crypto_algos}")
    print(f"AI Insights: {results.ai_summary}")
    
    # Export report
    await client.export_report(results, format="pdf")

asyncio.run(analyze_binary())
```

---

### 3. CLI Tools (For Quick Analysis)

**Perfect for**: One-off analysis, scripting, integration

```bash
# Analyze a binary
ghidrainsight analyze --file binary.elf

# Show all crypto algorithms
ghidrainsight analyze --file binary.elf --features crypto --verbose

# Taint analysis from specific source
ghidrainsight taint --file binary.elf --source user_input --sink system_call

# With AI insights
ghidrainsight analyze --file binary.elf --ai-summary --output report.json

# Check server status
ghidrainsight status

# View configuration
ghidrainsight config list
```

---

### 4. LLM Integration (ChatGPT / Claude)

**Perfect for**: AI assistants, automated security reviews

#### With Claude Desktop
```bash
# Configure Claude to use GhidraInsight
ghidrainsight integrate --provider claude --api-key $ANTHROPIC_API_KEY

# Binary analysis now available in Claude Desktop
```

#### With ChatGPT / OpenAI
```bash
# Setup OpenAI integration
ghidrainsight integrate --provider openai --api-key $OPENAI_API_KEY

# Now you can upload binaries in ChatGPT for analysis
```

See [examples/CLAUDE_INTEGRATION.md](examples/CLAUDE_INTEGRATION.md) and [examples/OPENAI_INTEGRATION.md](examples/OPENAI_INTEGRATION.md) for detailed setup.

---

### 5. REST API (For Custom Integration)

**Perfect for**: Third-party integrations, mobile apps, web services

```bash
# Analyze binary via HTTP
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "file": "/path/to/binary.elf",
    "features": ["crypto", "vulnerabilities"]
  }'

# Get analysis results
curl http://localhost:8000/api/analysis/{analysis_id}

# List available functions
curl http://localhost:8000/api/functions
```

Full API docs at [API_REFERENCE.md](docs/API_REFERENCE.md)

---

## 🎓 Examples & Tutorials

### Beginner Tutorials
- [🌟 First Analysis (5 min)](docs/QUICKSTART.md)
- [🎯 Dashboard Tour (10 min)](docs/tutorials/dashboard-tour.md) *(Coming soon)*
- [📚 Understanding Analysis Results](docs/tutorials/understanding-results.md) *(Coming soon)*

### Integration Guides
- [🤖 Claude Integration](examples/CLAUDE_INTEGRATION.md)
- [🔌 ChatGPT Integration](examples/OPENAI_INTEGRATION.md)
- [📡 MCP Server Setup](examples/MCP_SERVER.md)

### Advanced Topics
- [🏗️ Architecture Deep Dive](docs/ARCHITECTURE.md)
- [🔐 Security & Authentication](SECURITY.md)
- [🛠️ Custom Analysis Module Development](docs/development/custom-modules.md) *(Coming soon)*

### Real-World Examples
```bash
# Clone example binaries repository
git clone https://github.com/yourusername/ghidrainsight-examples.git
cd ghidrainsight-examples

# Run analysis on example files
ghidrainsight analyze --file binaries/crypto_sample.elf
ghidrainsight analyze --file binaries/vulnerable_c.elf
```

---

## 🏗 System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Access Layers                          │
├───────────────┬──────────────┬────────────┬──────────────┤
│ Web Dashboard │  Python SDK  │    CLI     │  LLM (MCP)   │
│  (React)      │  (Async)     │  (Click)   │  (Protocol)  │
└───────┬───────┴──────┬───────┴────┬───────┴──────┬───────┘
        │              │            │              │
        └──────────────┴────────────┴──────────────┘
                       │
        ┌──────────────▼──────────────┐
        │   REST API / WebSocket      │
        │   (Port 8000-8002)          │
        └──────────────┬──────────────┘
                       │
        ┌──────────────▼──────────────┐
        │  Python MCP Server          │
        │  (ghidrainsight core)       │
        └──────────────┬──────────────┘
                       │
        ┌──────────────▼──────────────┐
        │  Analysis Engine            │
        │  ├─ Crypto Detection        │
        │  ├─ Taint Analysis          │
        │  ├─ Vulnerability Detect.   │
        │  └─ Control Flow Analysis   │
        └──────────────┬──────────────┘
                       │
        ┌──────────────▼──────────────┐
        │  Ghidra Java Plugin         │
        │  (Binary decompilation)     │
        └─────────────────────────────┘
```

### Component Overview

| Component | Purpose | Technology |
|-----------|---------|-----------|
| **Web Dashboard** | Interactive UI for analysis | React + TypeScript |
| **Python MCP Server** | Core analysis & API | Python 3.9+ async |
| **Java Plugin** | Ghidra integration | Java 11+, Guice DI |
| **CLI Tools** | Command-line interface | Python Click |
| **REST API** | HTTP endpoints | FastAPI/Spark |

### Data Flow
```
Binary File → Ghidra Decompilation → Feature Extraction → 
AI Analysis → Vulnerability Scoring → Results JSON → 
Web UI / API Consumers
```

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed design documentation.

---

## 🧪 Testing & Quality

### Run Tests

```bash
# All tests
./scripts/test-all.sh

# Java tests
cd ghidra-plugin && ./gradlew test

# Python tests
cd python-mcp && pytest --cov=ghidrainsight -v

# React tests
cd web-dashboard && npm test
```

### Quality Metrics
- **Test Coverage**: Target 80%+
- **Code Quality**: SpotBugs, Black, ESLint
- **Type Checking**: mypy for Python, tsc for TypeScript
- **Security**: Dependabot + SAST scanning

### Generate Coverage Report
```bash
cd python-mcp
pytest --cov=ghidrainsight --cov-report=html
open htmlcov/index.html
```

Current status: See [QUALITY_REPORT.md](QUALITY_REPORT.md)

---

## 🚀 CI/CD Pipeline

**GitHub Actions** automatically:
- ✅ Runs all tests on push/PR
- 🔍 Checks code quality and security
- 📦 Publishes to PyPI and GitHub Releases
- 🐳 Builds & publishes Docker images
- 📖 Deploys documentation

View pipeline: [.github/workflows](.github/workflows)

---

## 🔐 Security & Authentication

### Supported Methods

```yaml
# Option 1: API Key (Simple)
headers:
  Authorization: "Bearer YOUR_API_KEY"

# Option 2: JWT (Recommended)
headers:
  Authorization: "Bearer <jwt_token>"

# Option 3: OAuth 2.0 (Enterprise)
# Configure via .env or config.yaml
OAUTH_PROVIDER=google
OAUTH_CLIENT_ID=...
```

### Configuration Example
```yaml
# config.yaml
server:
  host: 0.0.0.0
  port: 8000

auth:
  enabled: true
  method: jwt
  secret: ${GHIDRA_JWT_SECRET}

security:
  rate_limit:
    requests_per_minute: 60
  cors:
    allowed_origins:
      - http://localhost:3000
      - https://yourdomain.com
```

📖 Full security guide: [SECURITY.md](SECURITY.md)

---

## 📚 Documentation

| Document | Purpose | Audience |
|----------|---------|----------|
| [QUICKSTART.md](docs/QUICKSTART.md) | Get running in 5 minutes | New users |
| [INSTALLATION.md](INSTALLATION.md) | Detailed setup for all methods | Developers |
| [API_REFERENCE.md](docs/API_REFERENCE.md) | Complete API documentation | Integrators |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design & decisions | Contributors |
| [SECURITY.md](SECURITY.md) | Authentication & best practices | DevOps, Security teams |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development workflow | Contributors |
| [CHANGELOG.md](CHANGELOG.md) | Version history | Users |
| [ROADMAP.md](ROADMAP.md) | Future plans | Project stakeholders |

**View all docs locally**:
```bash
cd docs
npm install && npm start
# Opens at http://localhost:3000
```

---

## 🤝 Getting Help

### For Different Needs

**I have a question**  
→ [GitHub Discussions](https://github.com/ismailtsdln/GhidraInsight/discussions)

**I found a bug**  
→ [GitHub Issues](https://github.com/ismailtsdln/GhidraInsight/issues)

**I want to contribute**  
→ [CONTRIBUTING.md](CONTRIBUTING.md)

**I need enterprise support**  
→ Email: support@ghidrainsight.dev

### Community Resources
- 💬 [GitHub Discussions](https://github.com/ismailtsdln/GhidraInsight/discussions) - Q&A
- 🐛 [Issue Tracker](https://github.com/ismailtsdln/GhidraInsight/issues) - Bug reports
- 📖 [Full Documentation](docs/) - Comprehensive guides
- 🎥 [Video Tutorials](https://www.youtube.com/playlist?list=...) *(Coming soon)*

---

## 🛣️ Roadmap

### v1.0 ✅ (Current)
- ✅ Core binary analysis
- ✅ Crypto detection
- ✅ Web dashboard
- ✅ MCP integration
- ✅ Docker support

### v1.1 (Q1 2026)
- 🔄 Advanced ML models for pattern detection
- 🔄 Batch analysis API
- 🔄 Plugin marketplace
- 🔄 VS Code extension

### v1.2 (Q2 2026)
- 📋 Collaborative analysis features
- 📋 Cloud deployment templates
- 📋 Advanced report generation
- 📋 Mobile companion app

See [ROADMAP.md](ROADMAP.md) for detailed plans and contribute ideas!

---

## 📄 License & Attribution

**License**: Apache License 2.0  
See [LICENSE](LICENSE) file for details.

### Built Upon
- [NSA Ghidra](https://ghidra-sre.org/) - Binary analysis framework
- [Anthropic MCP](https://modelcontextprotocol.org/) - LLM protocol
- [Python Async](https://docs.python.org/3/library/asyncio.html) - Async runtime
- Open source community

---

## ⭐ Show Your Support

If GhidraInsight is helpful, please:
- ⭐ Star this repository
- 🐦 Share on social media
- 💬 Discuss with colleagues
- 🤝 Contribute improvements

---

## 📊 Project Statistics

| Metric | Value |
|--------|-------|
| Lines of Code | ~5,000+ |
| Components | 3 (Java, Python, React) |
| API Endpoints | 20+ |
| Test Coverage | 80%+ |
| Supported Formats | ELF, PE, Mach-O |
| LLM Integrations | Claude, ChatGPT, OpenAI |

---

## 🔗 Quick Links

**Getting Started**
- 🚀 [Installation Guide](INSTALLATION.md)
- ⚡ [Quick Start (5 min)](docs/QUICKSTART.md)
- 📖 [Full Documentation](docs/)

**Integration**
- 🤖 [Claude Setup](examples/CLAUDE_INTEGRATION.md)
- 🔌 [OpenAI Setup](examples/OPENAI_INTEGRATION.md)
- 📡 [MCP Protocol](examples/MCP_SERVER.md)
- 🦙 [Ollama (Local AI) Setup](examples/OLLAMA_INTEGRATION.md) **NEW**
- 🏠 [Local AI Models Guide](docs/LOCAL_AI_GUIDE.md) **NEW**

**Development**
- 🔧 [Architecture Guide](docs/ARCHITECTURE.md)
- 🛠️ [Contributing](CONTRIBUTING.md)
- 🧪 [Testing Guide](docs/testing/)

**Security**
- 🔐 [Security Policy](SECURITY.md)
- 🛡️ [Authentication Guide](docs/auth/)

---

<div align="center">

**Made with ❤️ for the reverse engineering community**

[Star ⭐](https://github.com/ismailtsdln/GhidraInsight) · [Report Bug 🐛](https://github.com/ismailtsdln/GhidraInsight/issues) · [Request Feature 💡](https://github.com/ismailtsdln/GhidraInsight/discussions)

</div>

---

*Last Updated: January 5, 2026*  
*Status: Production Ready v1.0*

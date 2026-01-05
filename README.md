# GhidraInsight 🔍

**AI-Assisted Reverse Engineering Platform Built on Ghidra and MCP**

GhidraInsight is a next-generation reverse engineering platform that combines the power of [Ghidra](https://ghidra-sre.org/) with AI-driven analysis, automated vulnerability detection, and a modern web dashboard. It provides a robust MCP (Model Context Protocol) server for seamless integration with AI assistants like ChatGPT, Claude, and other LLMs.

---

## 🚀 Features

- **🔬 Advanced Binary Analysis**
  - Automated cryptocurrency algorithm detection
  - Control flow anomaly detection
  - Taint analysis for data flow tracking
  - Function decompilation and symbol management

- **🤖 AI-Driven Insights**
  - Automated vulnerability identification with CVSS scoring
  - AI-powered remediation suggestions
  - Integration with ChatGPT, Claude, and other LLMs
  - Natural language queries on binary structure

- **🌐 Comprehensive MCP Server**
  - WebSocket, Server-Sent Events (SSE), and HTTP transports
  - Secure authentication (JWT, OAuth)
  - Rate limiting and request validation
  - Comprehensive error handling and retry mechanisms

- **💻 Modern Web Dashboard**
  - Real-time binary explorer
  - Interactive function graph visualization
  - AI chat interface for binary queries
  - Live analysis status and results

- **🧩 Extensible Architecture**
  - Plugin system for custom analysis modules
  - Dependency injection for loose coupling
  - Service-oriented design
  - Multiple transport implementations

- **🔐 Enterprise Security**
  - Authentication and authorization
  - Rate limiting
  - Audit logging
  - Optional telemetry collection
  - Docker containerization

---

## 📋 Requirements

### Minimum System Requirements
- **Java**: JDK 11 or higher
- **Python**: 3.9+
- **Node.js**: 18+ (for web dashboard)
- **Ghidra**: 11.0 or higher
- **RAM**: 4GB minimum (8GB+ recommended)

### Optional
- Docker & Docker Compose (for containerized deployment)
- GitHub Actions (for CI/CD)

---

## 🛠 Installation

### Quick Start (Docker)

```bash
docker-compose up -d
# Access dashboard at http://localhost:3000
```

### Manual Installation

#### 1. Java Ghidra Plugin

```bash
cd ghidra-plugin
./gradlew build
# JAR will be in build/libs/
```

Install the plugin in Ghidra:
1. Copy the JAR to `$GHIDRA_INSTALL_DIR/Extensions/Ghidra/plugins/`
2. Restart Ghidra
3. Enable the GhidraInsight plugin in Ghidra's plugin manager

#### 2. Python MCP Bridge

```bash
cd python-mcp
pip install -e .
```

Start the server:
```bash
ghidrainsight-server --host 0.0.0.0 --port 8000
```

#### 3. Web Dashboard

```bash
cd web-dashboard
npm install
npm run dev
# Access at http://localhost:5173
```

---

## 📖 Usage

### MCP Server

#### Start the Server
```bash
ghidrainsight-server --config config.yaml --log-level DEBUG
```

#### Via Python Client
```python
from ghidrainsight.client import GhidraInsightClient

client = GhidraInsightClient("http://localhost:8000")
results = client.analyze_binary("/path/to/binary", features=["crypto", "vulnerabilities"])
```

#### Via CLI
```bash
ghidrainsight analyze --file binary.elf --features crypto,taint,vulnerabilities
```

### Web Dashboard

1. **Upload Binary**: Drag and drop or select a binary file
2. **View Analysis**: See function list, imports, and decompilation
3. **Ask Questions**: Use AI chat to query the binary
4. **Export Results**: Download analysis reports in JSON/PDF

### Integrations

#### ChatGPT / Claude Integration

```bash
ghidrainsight integrate --provider openai --api-key $OPENAI_API_KEY
# Binary analysis is now available in ChatGPT
```

See [examples/integrations](examples/integrations) for detailed setup.

---

## 🏗 Architecture

```
GhidraInsight/
├── ghidra-plugin/           # Java Ghidra plugin
│   ├── src/main/java/       # Plugin source code
│   ├── build.gradle.kts     # Build configuration
│   └── plugin.properties    # Plugin metadata
├── python-mcp/              # Python MCP server & CLI
│   ├── ghidrainsight/       # Main package
│   ├── tests/               # Unit & integration tests
│   ├── pyproject.toml       # Python package config
│   └── requirements.txt     # Dependencies
├── web-dashboard/           # React web UI
│   ├── src/                 # React components
│   ├── package.json         # NPM config
│   └── vite.config.ts       # Vite config
├── docs/                    # Documentation (Docusaurus)
├── examples/                # Integration examples
├── .github/workflows/       # CI/CD pipelines
└── docker-compose.yml       # Docker orchestration
```

---

## 🧪 Testing

### Run All Tests
```bash
# Java
cd ghidra-plugin && ./gradlew test

# Python
cd python-mcp && pytest --cov=ghidrainsight

# React
cd web-dashboard && npm test
```

### Code Coverage
- **Target**: 80%+ coverage
- **Report**: Available in `build/coverage/` and `htmlcov/`

---

## 📚 API Reference

### MCP Resources

**`resource://ghidra/binary`**
- Analyze a binary file
- Parameters: `file`, `features` (array)
- Returns: Analysis results with vulnerabilities, crypto, etc.

**`resource://ghidra/function`**
- Analyze a specific function
- Parameters: `address`, `depth`
- Returns: Function metadata, control flow, decompilation

**`resource://ghidra/taint`**
- Perform taint analysis
- Parameters: `source`, `sink`
- Returns: Taint flow paths

See [API_REFERENCE.md](docs/API_REFERENCE.md) for complete documentation.

---

## 🔐 Security

### Authentication

GhidraInsight supports:
- **JWT**: Token-based authentication
- **OAuth 2.0**: External provider integration
- **API Key**: Simple key-based access

### Configuration

```yaml
auth:
  enabled: true
  provider: jwt
  secret: ${GHIDRA_JWT_SECRET}
  
security:
  rate_limit:
    requests_per_minute: 60
  cors:
    allowed_origins:
      - http://localhost:3000
      - https://yourdomain.com
```

See [SECURITY.md](SECURITY.md) for detailed security guidelines.

---

## 🧑‍💻 Contributing

We welcome contributions! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Development setup
- Code style guidelines
- Pull request process
- Testing requirements
- Commit message format

### Quick Contribution Steps

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit changes: `git commit -am 'Add new feature'`
4. Push to branch: `git push origin feature/my-feature`
5. Submit a pull request

---

## 🚀 CI/CD

GhidraInsight uses **GitHub Actions** for:
- ✅ Automated testing on push/PR
- 🔍 Code quality checks (SpotBugs, Black, ESLint)
- 📦 Build and release to PyPI and GitHub Releases
- 🐳 Docker image publishing
- 📖 Documentation deployment

See [.github/workflows](.github/workflows) for pipeline definitions.

---

## 📝 Documentation

Full documentation is available at:
- [docs/](docs/) - Docusaurus documentation site
- [API_REFERENCE.md](docs/API_REFERENCE.md) - Complete API docs
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
- [SECURITY.md](SECURITY.md) - Security policies

Run documentation locally:
```bash
cd docs
npm install && npm start
# Open http://localhost:3000
```

---

## 🤝 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/GhidraInsight/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/GhidraInsight/discussions)
- **Email**: support@ghidrainsight.dev

---

## 📄 License

GhidraInsight is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [NSA Ghidra](https://ghidra-sre.org/) - The foundation of our analysis engine
- [Anthropic](https://www.anthropic.com/) - MCP specification
- Community contributors and testers

---

**Built with ❤️ for the reverse engineering community**

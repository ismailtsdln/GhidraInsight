# Project Structure & File Overview

```
GhidraInsight/
│
├── README.md                          # Project overview
├── SECURITY.md                        # Security policies & guidelines
├── CONTRIBUTING.md                    # Contribution workflow
├── LICENSE                           # Apache 2.0 license
├── CHANGELOG.md                      # Version history
├── ROADMAP.md                        # Future plans
├── INSTALLATION.md                   # Setup instructions
├── .gitignore                        # Git ignore rules
├── .editorconfig                     # Editor settings
│
├── .github/
│   └── workflows/
│       └── ci-cd.yml                 # GitHub Actions CI/CD pipeline
│
├── ghidra-plugin/                    # Java Ghidra Plugin
│   ├── build.gradle.kts              # Gradle build configuration
│   ├── gradle.properties             # Gradle settings
│   ├── settings.gradle.kts           # Gradle settings
│   │
│   ├── src/main/java/com/ghidrainsight/
│   │   ├── GhidraInsightPlugin.java  # Main plugin class
│   │   │
│   │   ├── core/
│   │   │   ├── GhidraInsightCore.java       # DI container & core
│   │   │   ├── GhidraInsightModule.java     # Guice configuration
│   │   │   │
│   │   │   └── service/
│   │   │       ├── AnalysisService.java         # Interface
│   │   │       ├── AnalysisServiceImpl.java      # Implementation
│   │   │       ├── VulnerabilityDetector.java   # Interface
│   │   │       └── VulnerabilityDetectorImpl.java # Implementation
│   │   │
│   │   ├── analysis/
│   │   │   ├── CryptoDetector.java             # Interface
│   │   │   ├── CryptoDetectorImpl.java          # Implementation
│   │   │   ├── TaintAnalyzer.java              # Interface
│   │   │   └── TaintAnalyzerImpl.java           # Implementation
│   │   │
│   │   └── mcp/
│   │       └── MCPServer.java                 # MCP server
│   │
│   ├── src/test/java/com/ghidrainsight/
│   │   └── [test files]               # Unit tests
│   │
│   └── config/
│       └── checkstyle.xml             # Code style rules
│
├── python-mcp/                        # Python MCP Server & SDK
│   ├── pyproject.toml                 # Python package configuration
│   ├── setup.py                       # Setup script (legacy)
│   ├── setup.cfg                      # Setup configuration
│   │
│   ├── ghidrainsight/
│   │   ├── __init__.py                # Package init
│   │   │
│   │   ├── core/
│   │   │   ├── __init__.py
│   │   │   ├── client.py              # Python client SDK
│   │   │   └── models.py              # Data models
│   │   │
│   │   ├── mcp/
│   │   │   ├── __init__.py
│   │   │   ├── server.py              # MCP server
│   │   │   ├── transports.py          # Transport implementations
│   │   │   └── handlers.py            # Request handlers
│   │   │
│   │   ├── cli/
│   │   │   ├── __init__.py            # CLI entry point
│   │   │   ├── server.py              # Server command
│   │   │   └── analyze.py             # Analyze command
│   │   │
│   │   ├── auth.py                    # Authentication module
│   │   └── config.py                  # Configuration
│   │
│   ├── tests/
│   │   ├── conftest.py                # Pytest configuration
│   │   ├── test_client.py             # Client tests
│   │   ├── test_mcp_server.py         # MCP server tests
│   │   └── test_auth.py               # Auth tests
│   │
│   └── requirements.txt               # Dependencies
│
├── web-dashboard/                     # React Web UI
│   ├── package.json                   # NPM configuration
│   ├── package-lock.json              # Dependency lock
│   ├── tsconfig.json                  # TypeScript config
│   ├── tsconfig.node.json             # Node TypeScript config
│   ├── vite.config.ts                 # Vite bundler config
│   ├── vitest.config.ts               # Vitest test config
│   │
│   ├── index.html                     # HTML entry point
│   │
│   ├── src/
│   │   ├── main.tsx                   # React entry point
│   │   ├── App.tsx                    # Main App component
│   │   ├── App.css                    # App styling
│   │   ├── index.css                  # Global styles
│   │   │
│   │   ├── components/
│   │   │   ├── BinaryExplorer.tsx     # File upload/selection
│   │   │   ├── AnalysisPanel.tsx      # Analysis controls
│   │   │   ├── ChatInterface.tsx      # AI chat
│   │   │   ├── FunctionViewer.tsx     # Function browser
│   │   │   └── VulnerabilityList.tsx  # Issue display
│   │   │
│   │   ├── hooks/
│   │   │   └── [custom hooks]
│   │   │
│   │   ├── services/
│   │   │   └── api.ts                 # API client
│   │   │
│   │   └── types/
│   │       └── index.ts               # TypeScript types
│   │
│   ├── public/
│   │   ├── favicon.ico
│   │   └── [static assets]
│   │
│   └── Dockerfile                     # Docker build
│
├── docs/                              # Documentation
│   ├── README.md                      # Documentation home
│   ├── QUICKSTART.md                  # Quick start guide
│   ├── API_REFERENCE.md               # API documentation
│   ├── ARCHITECTURE.md                # System architecture
│   └── [other guides]
│
├── examples/                          # Integration examples
│   ├── CLAUDE_INTEGRATION.md          # Claude integration guide
│   ├── claude_integration.py          # Claude integration code
│   ├── OPENAI_INTEGRATION.md          # OpenAI integration guide
│   ├── openai_integration.py          # OpenAI integration code
│   ├── MCP_SERVER.md                  # MCP server guide
│   └── mcp_server.py                  # MCP server example
│
├── docker-compose.yml                 # Docker Compose orchestration
├── Dockerfile                         # Root Dockerfile (all-in-one)
├── Dockerfile.ghidra                  # Ghidra plugin Dockerfile
│
└── scripts/
    ├── setup.sh                       # Development setup
    ├── build.sh                       # Build script
    ├── test.sh                        # Test script
    ├── deploy.sh                      # Deployment script
    └── docker-build.sh                # Docker build script
```

---

## Key File Descriptions

### Documentation Files
- **README.md**: Project overview, features, quick start
- **SECURITY.md**: Security policies, authentication, best practices
- **CONTRIBUTING.md**: Development workflow, code style, PR process
- **INSTALLATION.md**: Detailed setup instructions
- **ROADMAP.md**: Future features and milestones
- **CHANGELOG.md**: Version history and releases

### Java Plugin
- **GhidraInsightPlugin.java**: Main Ghidra plugin entry point
- **GhidraInsightCore.java**: Dependency injection container
- **AnalysisService**: Coordinates all analysis engines
- **CryptoDetector**: Cryptocurrency algorithm detection
- **TaintAnalyzer**: Data flow and taint analysis
- **MCPServer**: MCP protocol implementation

### Python Package
- **client.py**: Python SDK for using the API
- **mcp/server.py**: MCP server implementation
- **cli/__init__.py**: Command-line interface
- **auth.py**: JWT and API key authentication
- **config.py**: Configuration management

### React Dashboard
- **App.tsx**: Main application component
- **BinaryExplorer.tsx**: File upload interface
- **AnalysisPanel.tsx**: Analysis controls and results
- **ChatInterface.tsx**: AI chat interface
- **vite.config.ts**: Development server and build config

### CI/CD
- **.github/workflows/ci-cd.yml**: GitHub Actions pipeline
- **Dockerfile**: All-in-one container
- **docker-compose.yml**: Multi-container orchestration

---

## File Statistics

| Component | Files | Languages | Lines (est.) |
|-----------|-------|-----------|--------------|
| Java Plugin | 12 | Java | 2,000 |
| Python MCP | 15 | Python | 2,500 |
| React Dashboard | 25 | TypeScript/React | 3,000 |
| Documentation | 8 | Markdown | 3,000 |
| Configuration | 10 | YAML/JSON | 500 |
| **Total** | **70+** | **5** | **11,000+** |

---

## Important Configurations

### build.gradle.kts
- Java compilation settings
- Dependency management
- Testing configuration
- Code quality plugins

### pyproject.toml
- Python version requirements
- Package dependencies
- Testing and linting tools
- Build system configuration

### package.json
- React and build dependencies
- Scripts for dev/build/test
- TypeScript configuration
- Testing framework setup

### docker-compose.yml
- Services definition
- Port mappings
- Environment variables
- Volume configuration

---

This comprehensive project structure supports:
- **Modularity**: Each component is independently buildable
- **Scalability**: Easy to add new modules
- **Maintainability**: Clear organization and separation of concerns
- **Testing**: Separate test directories for each component
- **Documentation**: Extensive inline and file-level docs

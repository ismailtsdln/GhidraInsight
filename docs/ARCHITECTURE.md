# Architecture Overview

## System Components

```
┌─────────────────────────────────────────────────────────────┐
│                    Web Dashboard (React)                     │
│  - Binary Explorer  - AI Chat  - Results Viewer             │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTP/WebSocket
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              Python MCP Bridge & REST API                    │
│  - HTTP Server  - WebSocket  - SSE  - Client SDK            │
└────────────────────────┬────────────────────────────────────┘
                         │ RPC/REST
                         ▼
┌─────────────────────────────────────────────────────────────┐
│            Java Ghidra Plugin (Analysis Engine)              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │  Crypto  │  │  Taint   │  │  Vuln.   │  │ Control  │   │
│  │ Detector │  │ Analyzer │  │Detector  │  │   Flow   │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │           Ghidra Core (Decompilation, CFG, etc.)       │ │
│  └────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
                              ▲
                              │ Binary File
                              │
                    [User's Binary File]
```

---

## Module Breakdown

### 1. Web Dashboard (React + TypeScript)

**Location**: `web-dashboard/`

**Components**:
- `BinaryExplorer`: File upload and selection
- `AnalysisPanel`: Real-time analysis status
- `ChatInterface`: AI-powered query system
- `FunctionViewer`: Function decompilation browser
- `VulnerabilityList`: Issue display with CVSS

**Tech Stack**:
- React 18+
- TypeScript
- Vite (bundler)
- Axios (HTTP client)
- Zustand (state management)

**Features**:
- Drag-and-drop binary upload
- Real-time analysis streaming
- Interactive function graphs
- Syntax-highlighted decompilation
- Responsive dark theme

---

### 2. Python MCP Bridge

**Location**: `python-mcp/`

**Modules**:
- `mcp/`: MCP server implementation
  - `server.py`: Main server
  - `transports.py`: WebSocket, SSE, HTTP
  - `handlers.py`: Request processing
- `cli/`: Command-line tools
  - `server.py`: Server startup
  - `analyze.py`: Batch analysis
  - `query.py`: Interactive queries
- `core/`: Core client SDK
  - `client.py`: Python client
  - `models.py`: Data structures
- `auth/`: Authentication
  - `jwt.py`: JWT handling
  - `oauth.py`: OAuth2 support
  - `api_key.py`: API key management

**Features**:
- Multi-transport support
- Async/await throughout
- Type hints (mypy compatible)
- Comprehensive error handling
- Rate limiting built-in

**Transport Support**:
```
WebSocket:  ws://localhost:8001
SSE:        http://localhost:8002/events
HTTP:       http://localhost:8000/api
```

---

### 3. Java Ghidra Plugin

**Location**: `ghidra-plugin/`

**Modules**:
- `core/`:
  - `GhidraInsightCore.java`: DI container & service coordinator
  - `GhidraInsightModule.java`: Guice configuration
  - `service/`: Service interfaces & implementations
    - `AnalysisService`: Main analysis orchestration
    - `VulnerabilityDetector`: Vuln detection
    - `SymbolManager`: Symbol resolution
- `analysis/`: Analysis engines
  - `CryptoDetector`: Crypto algorithm detection
  - `TaintAnalyzer`: Data flow tracking
  - `ControlFlowAnalyzer`: CFG anomaly detection
  - `VulnerabilityAnalyzer`: CVE/CWE mapping
- `mcp/`:
  - `MCPServer.java`: MCP server
  - `RestServer.java`: REST API endpoints
  - `WebSocketServer.java`: WebSocket transport
- `util/`:
  - `AddressResolver`: Symbol & function lookup
  - `Configuration`: Settings management

**Architecture Pattern**: Service-Oriented
- Loose coupling via interfaces
- Dependency injection (Guice)
- Stateless stateless analysis functions
- Exception handling wrappers

**Key Dependencies**:
- Ghidra SDK (11.x)
- Jackson (JSON)
- Spark (REST API)
- Guice (DI)
- Log4j (Logging)

---

## Data Flow

### 1. Binary Analysis Flow

```
User Upload
    ↓
[Web Dashboard] ──POST──→ [Python MCP]
    ↓                          ↓
                     Validate & Prepare
                          ↓
                      [Java Plugin]
                    (GhidraInsightCore)
                          ↓
                    ┌─────┴─────┬──────┐
                    ↓           ↓      ↓
               CryptoDetector TaintAnalyzer VulnDetector
                    ↓           ↓      ↓
                   (Ghidra API Analysis)
                    ↓           ↓      ↓
                    └─────┬─────┴──────┘
                          ↓
                  Format & Return Results
                          ↓
                   [Python MCP] ──JSON→ [Dashboard]
                          ↓
                      Display & Cache
```

### 2. AI Query Flow

```
User Question
    ↓
[Web Dashboard] ──Query──→ [Python MCP]
    ↓                          ↓
                  1. Retrieve analysis results
                  2. Build context
                          ↓
                    [LLM API] (e.g., Claude)
                          ↓
                  3. Stream response back
                          ↓
                [Web Dashboard] ──Stream──→ Display
```

---

## Communication Protocols

### REST API
- **Transport**: HTTP/HTTPS
- **Format**: JSON
- **Auth**: JWT or API Key
- **Rate Limit**: 60 req/min
- **Endpoints**: `/api/*`

### WebSocket
- **Transport**: ws/wss
- **Format**: JSON
- **Upgrade**: From HTTP
- **Use Case**: Real-time updates
- **Port**: 8001

### Server-Sent Events
- **Transport**: HTTP (long-polling)
- **Format**: JSON events
- **One-way**: Server → Client
- **Use Case**: Analysis updates
- **Port**: 8002

### MCP Protocol
- **Format**: JSON-RPC 2.0
- **Resources**: Tool definitions
- **Implements**: Anthropic MCP spec
- **Use Case**: LLM integration

---

## Dependency Injection (Java)

```java
// Guice module binding
public class GhidraInsightModule extends AbstractModule {
    @Override
    protected void configure() {
        bind(AnalysisService.class).to(AnalysisServiceImpl.class);
        bind(CryptoDetector.class).to(CryptoDetectorImpl.class);
        bind(TaintAnalyzer.class).to(TaintAnalyzerImpl.class);
        bind(VulnerabilityDetector.class)
            .to(VulnerabilityDetectorImpl.class);
    }
}

// Usage
Injector injector = Guice.createInjector(new GhidraInsightModule());
AnalysisService service = injector.getInstance(AnalysisService.class);
```

**Benefits**:
- Testable (mock dependencies)
- Extensible (add new implementations)
- Decoupled (interfaces only)

---

## Threading Model

### Python
- **Async/await**: `asyncio`
- **Thread pool**: For blocking I/O
- **Worker queue**: For long analysis

### Java
- **Thread pool**: Executors
- **Request threads**: Per connection
- **Analysis threads**: CPU-bound work
- **Scheduler**: Background tasks

---

## Scalability Considerations

### Horizontal Scaling
- Stateless analysis (no session state)
- Shared cache layer (Redis-ready)
- Load balancer compatible
- Database-agnostic

### Vertical Scaling
- Configurable heap/stack
- Batch size tuning
- Cache sizing
- Thread pool optimization

### Rate Limiting
- Per-IP tracking
- Per-user quotas
- Burst allowance
- Token bucket algorithm

---

## Extension Points

### Adding New Analysis Module

1. **Create analyzer class**:
```java
public interface CustomAnalyzer {
    JsonNode analyze(Program program);
}

public class CustomAnalyzerImpl implements CustomAnalyzer {
    @Override
    public JsonNode analyze(Program program) {
        // Analysis logic
    }
}
```

2. **Register in Guice**:
```java
bind(CustomAnalyzer.class).to(CustomAnalyzerImpl.class);
```

3. **Integrate into AnalysisService**:
```java
@Inject CustomAnalyzer customAnalyzer;

public JsonNode analyze(...) {
    result.set("custom", customAnalyzer.analyze(program));
}
```

---

## Performance Targets

| Operation | Target | Notes |
|-----------|--------|-------|
| Binary upload | < 2s | Network + parsing |
| Crypto detection | < 5s | Pattern matching |
| Taint analysis | < 30s | Graph traversal |
| Function analysis | < 1s | Per function |
| API response | < 500ms | Excluding analysis |

---

**For detailed implementation**, see component READMEs in each directory.

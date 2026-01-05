# GhidraInsight Quick Start Guide

## Installation (5 minutes)

### Option 1: Docker (Recommended)

```bash
git clone https://github.com/yourusername/GhidraInsight.git
cd GhidraInsight
docker-compose up
```

Access dashboard: `http://localhost:3000`

### Option 2: Manual Setup

#### 1. Java Ghidra Plugin
```bash
cd ghidra-plugin
./gradlew build
# Copy JAR to Ghidra extensions directory
cp build/libs/GhidraInsight-1.0.0.jar $GHIDRA_INSTALL_DIR/Extensions/Ghidra/
```

#### 2. Python MCP Server
```bash
cd python-mcp
pip install -e .
ghidrainsight-server --host 0.0.0.0 --port 8000
```

#### 3. Web Dashboard
```bash
cd web-dashboard
npm install
npm run dev
```

---

## Basic Usage

### 1. Upload Binary
1. Open `http://localhost:3000`
2. Drag & drop your binary or click to select

### 2. Run Analysis
1. Click "Start Analysis"
2. Select features:
   - ✅ Crypto Detection
   - ✅ Vulnerability Analysis
   - ✅ Taint Analysis
3. Wait for results (typically 30-60 seconds)

### 3. Review Results
- **Crypto**: Detected algorithms and their locations
- **Vulnerabilities**: CVSS scores and remediation hints
- **Taint**: Data flow paths from sources to sinks

### 4. Ask AI Questions
Use the chat interface to ask:
- "What functions use crypto?"
- "How does user input flow to system calls?"
- "What are the main security risks?"

---

## Command Line Usage

### Analyze a binary
```bash
ghidrainsight analyze --file binary.elf \
  --features crypto,taint,vulnerabilities \
  --output report.json
```

### Start server with custom config
```bash
ghidrainsight-server --config config.yaml \
  --host 0.0.0.0 \
  --port 8000 \
  --log-level DEBUG
```

### Query the API
```bash
curl -X POST http://localhost:8000/api/analyze \
  -F "file=@binary.elf" \
  -H "X-API-Key: your-api-key" \
  -d "features=crypto,vulnerabilities"
```

---

## Python Integration

```python
import asyncio
from ghidrainsight import GhidraInsightClient

async def main():
    async with GhidraInsightClient("http://localhost:8000") as client:
        # Analyze binary
        results = await client.analyze_binary(
            "binary.elf",
            features=["crypto", "vulnerabilities"]
        )
        print(f"Found {len(results['vulnerabilities'])} issues")
        
        # Analyze specific function
        function = await client.analyze_function("0x401234")
        print(function)

asyncio.run(main())
```

---

## AI Integration (ChatGPT/Claude)

### Using GhidraInsight with ChatGPT
```python
import openai

response = openai.ChatCompletion.create(
    model="gpt-4",
    tools=[{
        "type": "function",
        "function": {
            "name": "analyze_binary",
            "description": "Analyze a binary with GhidraInsight",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string"}
                },
                "required": ["file_path"]
            }
        }
    }],
    messages=[
        {"role": "user", "content": "Analyze this binary: binary.elf"}
    ]
)
```

---

## Configuration

### Environment Variables
```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
export JWT_SECRET=your-secret-key-here
export API_KEY=your-api-key-here
export LOG_LEVEL=INFO
export RATE_LIMIT=60
```

### Config File (YAML)
```yaml
server:
  host: 0.0.0.0
  port: 8000
  
auth:
  enabled: true
  provider: jwt
  secret: ${JWT_SECRET}
  
security:
  rate_limit:
    requests_per_minute: 60
  cors:
    allowed_origins:
      - http://localhost:3000
```

---

## Troubleshooting

### Port Already in Use
```bash
# Find process using port 8000
lsof -i :8000

# Kill the process
kill -9 <PID>

# Or use different port
ghidrainsight-server --port 8001
```

### Out of Memory
```bash
# Increase JVM memory for Java plugin
export JAVA_OPTS="-Xmx8g"
```

### WebSocket Connection Failed
- Ensure firewall allows port 8001
- Check CORS configuration
- Verify server is running

### High Memory Usage
- Close unused analysis tabs
- Reduce file size or split analysis
- Check for memory leaks with `jmap`

---

## Next Steps

- 📖 Read [API_REFERENCE.md](API_REFERENCE.md) for detailed endpoints
- 🔐 Review [SECURITY.md](../SECURITY.md) for security practices
- 🚀 Check [examples/](../examples/) for integration samples
- 🐛 Report issues on [GitHub Issues](https://github.com/yourusername/GhidraInsight/issues)

---

**Happy analyzing! 🔍**

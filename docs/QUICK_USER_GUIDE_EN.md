# GhidraInsight - User-Friendly Quick Guide

**Date**: January 5, 2026  
**Version**: 1.0  
**Status**: Production Ready

---

## 🚀 Getting Started (Only 3 Commands!)

### Option 1: Docker (Easiest) ⭐
```bash
git clone https://github.com/ismailtsdln/GhidraInsight.git
cd GhidraInsight
docker-compose up -d && open http://localhost:3000
```

**Commands**:
```bash
./scripts/startup.sh docker    # Start
./scripts/startup.sh stop      # Stop
./scripts/troubleshoot.sh      # Troubleshoot
```

### Option 2: Automated Setup (macOS/Linux)
```bash
chmod +x scripts/setup.sh
./scripts/setup.sh --mode=all
./scripts/startup.sh all
```

### Option 3: Python Only
```bash
pip install ghidrainsight
ghidrainsight analyze --file binary.elf
```

---

## 🎯 Common Tasks

### 📊 Performing Binary Analysis

**Using Web Dashboard** (Recommended):
```
1. Open http://localhost:3000
2. Drag your file in
3. View results
4. Ask AI questions via chat
```

**Using CLI**:
```bash
ghidrainsight analyze --file binary.elf --output report.json
```

**Using Python SDK**:
```python
from ghidrainsight.client import GhidraInsightClient
client = GhidraInsightClient("http://localhost:8000")
results = await client.analyze("/path/to/binary")
```

---

### 🤖 Using AI Chat

#### With Claude
```bash
# 1. Open Claude Desktop
# 2. Settings → Preferences → Data Sources
# 3. Add GhidraInsight: http://localhost:8000

# Or via CLI:
ghidrainsight integrate --provider claude --api-key $ANTHROPIC_API_KEY
```

#### With ChatGPT
```bash
ghidrainsight integrate --provider openai --api-key $OPENAI_API_KEY
# Now you can upload binaries in ChatGPT
```

---

### 🔍 Finding Specific Things

**Crypto Algorithms**:
```bash
ghidrainsight analyze --file binary.elf --features crypto --verbose
```

**Security Vulnerabilities**:
```bash
ghidrainsight analyze --file binary.elf --features vulnerabilities
```

**Data Flow Analysis**:
```bash
ghidrainsight taint --file binary.elf --source user_input --sink system_call
```

---

## 🛠️ Configuration

### Basic Setup
```bash
# Interactive configuration
ghidrainsight config setup --guided

# View configuration
ghidrainsight config list

# Change values
ghidrainsight config set api.port 9000
```

### .env File (Optional)
```bash
GHIDRA_SERVER_HOST=0.0.0.0
GHIDRA_SERVER_PORT=8000
GHIDRA_JWT_SECRET=your-secret-key
```

---

## 🆘 Troubleshooting

### Quick Diagnostics
```bash
./scripts/troubleshoot.sh        # Interactive mode
./scripts/troubleshoot.sh --full # Complete diagnostics
```

### Common Issues

**"Docker not found"**
```bash
# Solution: Install Docker Desktop
# https://www.docker.com/products/docker-desktop
```

**"Port 3000 already in use"**
```bash
# Solution: Stop existing process
lsof -ti:3000 | xargs kill -9
```

**"Python module not found"**
```bash
# Solution:
pip install --upgrade ghidrainsight
```

**"Connection refused"**
```bash
# Check if server is running:
docker-compose ps
# View logs:
docker-compose logs python-mcp
```

---

## 📚 Documentation

| Document | Content | For Whom |
|----------|---------|----------|
| [README.md](../README.md) | Overview | All Users |
| [EASE_OF_USE_IMPROVEMENTS_EN.md](EASE_OF_USE_IMPROVEMENTS_EN.md) | UX Enhancements | Developers |
| [INSTALLATION.md](INSTALLATION.md) | Installation Details | Developers |
| [SECURITY.md](SECURITY.md) | Security Guide | DevOps |
| [API_REFERENCE.md](API_REFERENCE.md) | API Documentation | Integrators |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Code Contribution | Developers |

---

## 🔗 Quick Links

**Setup Scripts**:
- `./scripts/setup.sh` - Installation (First time)
- `./scripts/startup.sh` - Start services
- `./scripts/troubleshoot.sh` - Troubleshooting

**CLI Commands**:
```bash
ghidrainsight --version          # Version
ghidrainsight --help             # Help
ghidrainsight analyze --help     # Analyze help
ghidrainsight config --help      # Configuration help
```

**Web Interfaces**:
- 🌐 Dashboard: http://localhost:3000
- 🔌 API: http://localhost:8000
- 📡 WebSocket: ws://localhost:8001

---

## 💡 Tips & Tricks

### 1. Docker Quick Commands
```bash
# View logs
docker-compose logs -f

# Specific service logs
docker-compose logs -f python-mcp

# Get shell access
docker-compose exec python-mcp bash

# Edit configuration
nano docker-compose.yml
```

### 2. CLI Auto-Completion
```bash
# Bash (macOS/Linux)
eval "$(ghidrainsight --bash-complete)"

# Zsh
eval "$(ghidrainsight --zsh-complete)"
```

### 3. Batch Analysis
```bash
# Analyze all files in directory
for file in binaries/*; do
    ghidrainsight analyze --file "$file" --output "results/$(basename $file).json"
done
```

### 4. CI/CD Integration
```yaml
# .github/workflows/security-check.yml
name: Security Analysis
on: [push, pull_request]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Analyze Binaries
        run: |
          pip install ghidrainsight
          ghidrainsight analyze --file ./binary --strict
```

### 5. Custom Analyzer
```python
# custom_analyzer.py
from ghidrainsight.client import GhidraInsightClient
import asyncio

async def custom_analysis(binary_path):
    client = GhidraInsightClient()
    
    # Standard analysis
    results = await client.analyze(binary_path)
    
    # Custom processing
    for vuln in results.vulnerabilities:
        if vuln.severity == "CRITICAL":
            print(f"🔴 {vuln.name}: {vuln.description}")
    
    return results

asyncio.run(custom_analysis("./binary.elf"))
```

---

## 🎓 Learning Resources

### For Beginners
1. **5-Minute Quick Start**
   - `cat docs/QUICKSTART.md`
   - Perform your first analysis

2. **10-Minute Dashboard Tour**
   - Open http://localhost:3000
   - Upload sample file
   - Explore features

3. **CLI Tutorial**
   ```bash
   ghidrainsight analyze --help
   ghidrainsight taint --help
   ```

### Intermediate Level
- [API_REFERENCE.md](API_REFERENCE.md) - REST API
- [ARCHITECTURE.md](ARCHITECTURE.md) - System design
- Integration guides (Claude, OpenAI, MCP)

### Advanced Level
- Writing custom analyzers
- Docker compose customization
- Production deployment

---

## 📞 Getting Help

### Quick Diagnostics
```bash
# Collect system info (for reporting)
./scripts/troubleshoot.sh --full
```

### Contact Channels
- 💬 [Discussions](https://github.com/ismailtsdln/GhidraInsight/discussions)
- 🐛 [Issues](https://github.com/ismailtsdln/GhidraInsight/issues)
- 📧 Email: support@ghidrainsight.dev

---

## ✨ Useful Resources

### Official Projects
- [Ghidra Official Site](https://ghidra-sre.org/)
- [Ghidra Documentation](https://ghidra-sre.org/releaseNotes)
- [MCP Protocol](https://modelcontextprotocol.org/)
- [Python Async Guide](https://docs.python.org/3/library/asyncio.html)

### Community & Support
- 💬 [Ollama Discussions](https://github.com/ollama/ollama/discussions)
- 🐛 [Ollama Issues](https://github.com/ollama/ollama/issues)
- 🔗 [GhidraInsight Discussions](https://github.com/ismailtsdln/GhidraInsight/discussions)

---

## 🎉 Next Steps

1. ✅ Install: `./scripts/setup.sh --mode=all`
2. 🚀 Start: `./scripts/startup.sh docker`
3. 🌐 Open: http://localhost:3000
4. 📊 Analyze your first binary
5. 🤖 Try Claude/ChatGPT integration
6. 📖 Read documentation
7. 💬 Send feedback

---

**Happy analyzing! 🔍**

*Last Updated: January 5, 2026*

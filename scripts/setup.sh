#!/bin/bash

# GhidraInsight Project Setup Script

set -e

echo "🚀 GhidraInsight Development Setup"
echo "=================================="

# Check system requirements
echo "✓ Checking system requirements..."

# Check Java
if ! command -v java &> /dev/null; then
    echo "❌ Java not found. Please install JDK 11+"
    exit 1
fi
JAVA_VERSION=$(java -version 2>&1 | head -1)
echo "  Java: $JAVA_VERSION"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 not found. Please install Python 3.9+"
    exit 1
fi
PYTHON_VERSION=$(python3 --version)
echo "  Python: $PYTHON_VERSION"

# Check Node.js
if ! command -v node &> /dev/null; then
    echo "❌ Node.js not found. Please install Node.js 18+"
    exit 1
fi
NODE_VERSION=$(node --version)
echo "  Node.js: $NODE_VERSION"

# Check Gradle
echo "✓ Checking Gradle..."
if [ ! -f "ghidra-plugin/gradlew" ]; then
    echo "⚠️  Gradle wrapper not found, using system gradle"
fi

# Setup Java Plugin
echo ""
echo "📦 Setting up Java Ghidra plugin..."
cd ghidra-plugin
if [ ! -f "gradlew" ]; then
    chmod +x gradlew
fi
echo "  Building plugin..."
./gradlew build -q
cd ..

# Setup Python MCP
echo ""
echo "📦 Setting up Python MCP server..."
cd python-mcp
echo "  Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate
echo "  Installing dependencies..."
pip install -q -e ".[dev]"
deactivate
cd ..

# Setup Web Dashboard
echo ""
echo "📦 Setting up web dashboard..."
cd web-dashboard
echo "  Installing dependencies..."
npm install -q
cd ..

# Create .env file if not exists
echo ""
echo "⚙️  Creating configuration files..."
if [ ! -f ".env" ]; then
    cat > .env << 'EOF'
# GhidraInsight Configuration
GHIDRA_INSTALL_DIR=/opt/ghidra-11.0
SERVER_HOST=0.0.0.0
SERVER_PORT=8000
SERVER_LOG_LEVEL=INFO

JWT_SECRET=change-this-to-a-secure-key-at-least-32-chars
JWT_ALGORITHM=HS256
API_KEY=your-api-key-here

RATE_LIMIT=60
CORS_ORIGINS=http://localhost:3000,http://localhost:5173

TELEMETRY_ENABLED=false
EOF
    echo "  Created .env (configure with your settings)"
fi

# Create directories
echo ""
echo "📁 Creating required directories..."
mkdir -p logs
mkdir -p data
mkdir -p cache

# Summary
echo ""
echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "1. Set GHIDRA_INSTALL_DIR in .env"
echo "2. Configure JWT_SECRET and API_KEY"
echo "3. Run: make start"
echo ""
echo "Or start components individually:"
echo "  - Java: cd ghidra-plugin && ./gradlew run"
echo "  - Python: cd python-mcp && source venv/bin/activate && ghidrainsight-server"
echo "  - Web: cd web-dashboard && npm run dev"

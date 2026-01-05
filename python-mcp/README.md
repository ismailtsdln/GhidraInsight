# GhidraInsight MCP Server

AI-driven reverse engineering platform with Ghidra and MCP support.

## Installation

```bash
pip install -e .
```

## Usage

```python
from ghidrainsight import MCPServer

server = MCPServer()
await server.start()
```

## Features

- Binary analysis with parallel processing
- Caching for improved performance
- PostgreSQL database support
- WebSocket and SSE streaming

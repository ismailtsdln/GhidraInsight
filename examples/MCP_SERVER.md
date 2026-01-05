# MCP Server Example

This example shows how to build an MCP (Model Context Protocol) server that exposes GhidraInsight resources.

## MCP Resources

### `resource://ghidra/binary`

Analyze a binary file:

```json
{
  "jsonrpc": "2.0",
  "method": "resources/read",
  "params": {
    "uri": "resource://ghidra/binary",
    "data": {
      "file": "binary.elf",
      "features": ["crypto", "taint", "vulnerabilities"]
    }
  }
}
```

### `resource://ghidra/function/{address}`

Analyze a function at an address:

```json
{
  "jsonrpc": "2.0",
  "method": "resources/read",
  "params": {
    "uri": "resource://ghidra/function/0x401234",
    "data": {
      "depth": 2
    }
  }
}
```

## MCP Tools

### `ghidra_analyze`

Tool for binary analysis:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "ghidra_analyze",
    "arguments": {
      "file": "binary.elf",
      "features": ["crypto", "vulnerabilities"]
    }
  }
}
```

## Usage in Claude/ChatGPT

With MCP configured, Claude can use GhidraInsight directly:

```
User: "Analyze binary.elf for vulnerabilities"

Claude: [Uses ghidra_analyze tool]

Claude: "Based on the analysis, I found 3 high-severity issues..."
```

---

See [mcp_server.py](./mcp_server.py) for implementation details.

# GhidraInsight API Reference

## Overview

GhidraInsight provides both REST API and MCP (Model Context Protocol) interfaces for programmatic access to binary analysis capabilities.

---

## REST API

### Base URL

```
http://localhost:8000/api
```

### Authentication

All requests should include either:

#### API Key Header
```
X-API-Key: your-api-key-here
```

#### JWT Bearer Token
```
Authorization: Bearer <jwt-token>
```

---

## Endpoints

### Binary Analysis

#### `POST /analyze`

Analyze a binary file with specified features.

**Request:**
```bash
curl -X POST http://localhost:8000/api/analyze \
  -F "file=@binary.elf" \
  -H "X-API-Key: your-api-key" \
  -d "features=crypto,taint,vulnerabilities"
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `file` | File | Binary file to analyze |
| `features` | String (comma-separated) | Features: `crypto`, `taint`, `vulnerabilities`, `control_flow` |
| `timeout` | Integer | Analysis timeout in seconds (default: 300) |

**Response (200 OK):**
```json
{
  "status": "success",
  "binary": "binary.elf",
  "analysis": {
    "crypto": [
      {
        "algorithm": "AES",
        "confidence": 0.95,
        "locations": ["0x401234", "0x401456"]
      }
    ],
    "vulnerabilities": [
      {
        "type": "buffer_overflow",
        "severity": "high",
        "cvss": 8.5,
        "address": "0x401234",
        "recommendation": "Add bounds checking"
      }
    ],
    "taint": [
      {
        "source": "0x401000",
        "sink": "0x402000",
        "path": ["0x401000", "0x401100", "0x402000"]
      }
    ]
  },
  "timestamp": "2024-01-05T10:30:45Z"
}
```

**Response (400 Bad Request):**
```json
{
  "status": "error",
  "error": "File exceeds 1GB limit",
  "code": "FILE_TOO_LARGE"
}
```

---

### Function Analysis

#### `GET /function/{address}`

Analyze a specific function at a given address.

**Request:**
```bash
curl http://localhost:8000/api/function/0x401234 \
  -H "X-API-Key: your-api-key" \
  -d "depth=2"
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `address` | String | Function address (hex format: `0x401234`) |
| `depth` | Integer | Analysis depth (1-5, default: 1) |

**Response (200 OK):**
```json
{
  "status": "success",
  "address": "0x401234",
  "function": {
    "name": "main",
    "size": 512,
    "parameters": 2,
    "variables": 8,
    "basic_blocks": 5,
    "calls": ["malloc", "printf", "exit"],
    "callers": ["_start"],
    "decompiled_code": "int main(int argc, char **argv) { ... }"
  },
  "analysis": {
    "control_flow_anomalies": [
      {
        "type": "unreachable_code",
        "address": "0x401345",
        "severity": "low"
      }
    ],
    "data_flow": {
      "parameter_taint": [
        {
          "parameter": "argv[1]",
          "flows_to": ["sprintf", "system"]
        }
      ]
    }
  }
}
```

---

### Taint Analysis

#### `GET /taint`

Perform taint analysis between source and sink.

**Request:**
```bash
curl http://localhost:8000/api/taint \
  -H "X-API-Key: your-api-key" \
  -d "source=0x401000&sink=0x402000"
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `source` | String | Source address (hex format) |
| `sink` | String | Sink address (hex format) |
| `max_depth` | Integer | Maximum recursion depth (default: 10) |

**Response (200 OK):**
```json
{
  "status": "success",
  "source": "0x401000",
  "sink": "0x402000",
  "paths": [
    {
      "path": ["0x401000", "0x401100", "0x401200", "0x402000"],
      "transformations": ["mov", "add", "call"],
      "risk_level": "high",
      "reason": "User input reaches system call without validation"
    }
  ],
  "reachable": true
}
```

---

### Vulnerability Scoring

#### `POST /vulnerabilities/score`

Get CVSS score for a vulnerability.

**Request:**
```bash
curl -X POST http://localhost:8000/api/vulnerabilities/score \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "type": "buffer_overflow",
    "impact": "high",
    "exploitability": "high",
    "scope": "changed"
  }'
```

**Response (200 OK):**
```json
{
  "status": "success",
  "type": "buffer_overflow",
  "cvss_v3": "8.5",
  "severity": "HIGH",
  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L",
  "description": "Allows remote attacker to execute code"
}
```

---

### Server Status

#### `GET /status`

Get server status and health information.

**Request:**
```bash
curl http://localhost:8000/api/status
```

**Response (200 OK):**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime_seconds": 3600,
  "services": {
    "crypto_detector": "ready",
    "taint_analyzer": "ready",
    "vulnerability_detector": "ready"
  },
  "memory_usage_mb": 512,
  "active_analyses": 2,
  "rate_limit": {
    "requests_per_minute": 60,
    "remaining": 45
  }
}
```

---

## MCP Protocol

### Resource: `resource://ghidra/binary`

Analyze a binary file via MCP.

**Call:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "resources/read",
  "params": {
    "uri": "resource://ghidra/binary",
    "format": "text",
    "data": {
      "file": "binary.elf",
      "features": ["crypto", "taint", "vulnerabilities"]
    }
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "contents": [
      {
        "uri": "resource://ghidra/binary/crypto",
        "mimeType": "application/json",
        "text": "{...}"
      }
    ]
  }
}
```

### Tool: `ghidra_analyze`

Analyze a binary using MCP tool interface.

**Call:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "ghidra_analyze",
    "arguments": {
      "file_path": "/path/to/binary",
      "features": ["crypto", "vulnerabilities"]
    }
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Analysis completed: 5 vulnerabilities found, 3 crypto algorithms detected"
      }
    ]
  }
}
```

---

## Error Handling

### Common Error Codes

| Code | Status | Description |
|------|--------|-------------|
| `FILE_NOT_FOUND` | 404 | Binary file not found |
| `FILE_TOO_LARGE` | 413 | File exceeds size limit (1GB) |
| `INVALID_FORMAT` | 400 | Unsupported binary format |
| `UNAUTHORIZED` | 401 | Invalid or missing credentials |
| `RATE_LIMITED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Server error |

### Error Response Format

```json
{
  "status": "error",
  "error": "Buffer overflow detected without proper bounds checking",
  "code": "ANALYSIS_FAILED",
  "timestamp": "2024-01-05T10:30:45Z"
}
```

---

## Rate Limiting

- **Default**: 60 requests per minute
- **Burst**: Up to 10 requests at once
- **Headers**:
  - `X-RateLimit-Limit`: 60
  - `X-RateLimit-Remaining`: 45
  - `X-RateLimit-Reset`: 1609776645

---

## WebSocket API

### Connection

```javascript
const ws = new WebSocket('ws://localhost:8001/api/ws');

ws.onopen = () => {
  ws.send(JSON.stringify({
    type: 'analyze',
    file: 'binary.elf',
    features: ['crypto', 'vulnerabilities']
  }));
};

ws.onmessage = (event) => {
  const result = JSON.parse(event.data);
  console.log('Analysis result:', result);
};
```

---

## Python Client

```python
from ghidrainsight import GhidraInsightClient

client = GhidraInsightClient("http://localhost:8000")

# Analyze binary
results = await client.analyze_binary(
    "/path/to/binary",
    features=["crypto", "taint", "vulnerabilities"]
)

# Analyze function
function = await client.analyze_function("0x401234", depth=2)

# Taint analysis
taint = await client.taint_analysis("0x401000", "0x402000")

# Get status
status = await client.get_status()
```

---

## OpenAPI Specification

Full OpenAPI 3.0 specification available at:

```
GET /api/openapi.json
```

---

## Rate Limits & Quotas

| Operation | Limit |
|-----------|-------|
| Analyze binary (max 1GB) | 10 per minute |
| Function analysis | 100 per minute |
| Taint analysis | 50 per minute |
| WebSocket connections | 100 concurrent |

---

## Changelog

### Version 1.0.0
- Initial release with crypto detection, taint analysis, vulnerability scoring
- REST, WebSocket, and MCP protocol support
- JWT and API key authentication

---

**Last Updated**: January 5, 2026

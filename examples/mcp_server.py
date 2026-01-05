#!/usr/bin/env python3

"""MCP Server implementation for GhidraInsight."""

import json
from typing import Any, Dict, List

from ghidrainsight.mcp import MCPServer
from ghidrainsight import GhidraInsightClient


class GhidraInsightMCPServer(MCPServer):
    """MCP Server exposing GhidraInsight as resources."""
    
    def __init__(self, ghidra_url: str = "http://localhost:8000"):
        """Initialize MCP server."""
        super().__init__()
        self.ghidra_client = GhidraInsightClient(ghidra_url)
    
    async def handle_resource_read(self, uri: str, data: Dict[str, Any]) -> str:
        """Handle resource read requests."""
        if uri.startswith("resource://ghidra/binary"):
            return await self._handle_binary_analysis(data)
        elif uri.startswith("resource://ghidra/function/"):
            address = uri.split("/")[-1]
            return await self._handle_function_analysis(address, data)
        else:
            raise ValueError(f"Unknown resource: {uri}")
    
    async def _handle_binary_analysis(self, data: Dict[str, Any]) -> str:
        """Handle binary analysis request."""
        file_path = data.get("file")
        features = data.get("features", ["crypto", "taint", "vulnerabilities"])
        
        result = await self.ghidra_client.analyze_binary(file_path, features)
        return json.dumps(result, indent=2)
    
    async def _handle_function_analysis(
        self,
        address: str,
        data: Dict[str, Any],
    ) -> str:
        """Handle function analysis request."""
        depth = data.get("depth", 1)
        
        result = await self.ghidra_client.analyze_function(address, depth)
        return json.dumps(result, indent=2)
    
    def get_resources(self) -> List[Dict[str, Any]]:
        """Get available resources."""
        return [
            {
                "uri": "resource://ghidra/binary",
                "name": "Binary Analysis",
                "description": "Analyze a binary file for vulnerabilities, crypto, and taint",
                "mimeType": "application/json"
            },
            {
                "uri": "resource://ghidra/function/{address}",
                "name": "Function Analysis",
                "description": "Analyze a specific function at an address",
                "mimeType": "application/json"
            }
        ]
    
    def get_tools(self) -> List[Dict[str, Any]]:
        """Get available tools."""
        return [
            {
                "name": "ghidra_analyze",
                "description": "Analyze a binary file with GhidraInsight",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "file": {
                            "type": "string",
                            "description": "Path to binary file"
                        },
                        "features": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Analysis features: crypto, taint, vulnerabilities"
                        }
                    },
                    "required": ["file"]
                }
            },
            {
                "name": "ghidra_function",
                "description": "Analyze a specific function",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "address": {
                            "type": "string",
                            "description": "Function address (hex format, e.g., 0x401234)"
                        },
                        "depth": {
                            "type": "integer",
                            "description": "Analysis depth (1-5)",
                            "default": 1
                        }
                    },
                    "required": ["address"]
                }
            }
        ]


async def main():
    """Start MCP server."""
    server = GhidraInsightMCPServer("http://localhost:8000")
    
    print("GhidraInsight MCP Server")
    print(f"Resources: {[r['name'] for r in server.get_resources()]}")
    print(f"Tools: {[t['name'] for t in server.get_tools()]}")
    
    await server.start()


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())

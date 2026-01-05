"""Core client for GhidraInsight MCP server."""

import asyncio
from typing import Any, Dict, List, Optional
from loguru import logger
import httpx

class GhidraInsightClient:
    """Client for communicating with GhidraInsight MCP server."""
    
    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        api_key: Optional[str] = None,
        timeout: int = 30,
    ):
        """
        Initialize the client.
        
        Args:
            base_url: Server base URL
            api_key: Optional API key for authentication
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.client = httpx.Client(timeout=timeout)
        
        if api_key:
            self.client.headers["X-API-Key"] = api_key
    
    async def analyze_binary(
        self,
        file_path: str,
        features: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze a binary file.
        
        Args:
            file_path: Path to binary file
            features: List of analysis features (crypto, taint, vulnerabilities)
            
        Returns:
            Analysis results
        """
        if features is None:
            features = ["crypto", "taint", "vulnerabilities"]
        
        logger.info(f"Analyzing binary: {file_path}")
        
        with open(file_path, "rb") as f:
            files = {"file": f}
            params = {"features": ",".join(features)}
            
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/api/analyze",
                    files=files,
                    params=params,
                )
                response.raise_for_status()
                return response.json()
    
    async def analyze_function(
        self,
        function_address: str,
        depth: int = 1,
    ) -> Dict[str, Any]:
        """
        Analyze a specific function.
        
        Args:
            function_address: Function address in hex format (e.g., "0x401000")
            depth: Analysis depth (1-5)
            
        Returns:
            Function analysis results
        """
        logger.debug(f"Analyzing function at {function_address}")
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(
                f"{self.base_url}/api/function/{function_address}",
                params={"depth": depth},
            )
            response.raise_for_status()
            return response.json()
    
    async def taint_analysis(
        self,
        source: str,
        sink: str,
    ) -> Dict[str, Any]:
        """
        Perform taint analysis between source and sink.
        
        Args:
            source: Source address
            sink: Sink address
            
        Returns:
            Taint flow paths
        """
        logger.debug(f"Taint analysis from {source} to {sink}")
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(
                f"{self.base_url}/api/taint",
                params={"source": source, "sink": sink},
            )
            response.raise_for_status()
            return response.json()
    
    async def get_status(self) -> Dict[str, Any]:
        """
        Get server status.
        
        Returns:
            Server status information
        """
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(f"{self.base_url}/api/status")
            response.raise_for_status()
            return response.json()
    
    def close(self) -> None:
        """Close the client connection."""
        self.client.close()
    
    async def __aenter__(self) -> "GhidraInsightClient":
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        self.close()

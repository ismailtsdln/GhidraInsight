"""GhidraInsight client SDK with comprehensive error handling and retry logic."""

import logging
from typing import Optional, Dict, Any, List
import asyncio
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class ClientError(Exception):
    """Base client error."""
    pass


class ConnectionError(ClientError):
    """Connection-related error."""
    pass


class TimeoutError(ClientError):
    """Request timeout."""
    pass


class ValidationError(ClientError):
    """Input validation error."""
    pass


@dataclass
class AnalysisResult:
    """Represents analysis results from GhidraInsight."""
    
    binary_name: str
    analysis_type: str
    findings: List[Dict[str, Any]]
    confidence: float
    duration_ms: int
    timestamp: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "binary_name": self.binary_name,
            "analysis_type": self.analysis_type,
            "findings": self.findings,
            "confidence": self.confidence,
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp,
        }


class GhidraInsightClient:
    """
    Async client for GhidraInsight MCP server.
    
    Provides methods for binary analysis, function analysis, taint analysis,
    and vulnerability detection.
    """
    
    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        api_key: Optional[str] = None,
        token: Optional[str] = None,
        timeout: int = 30,
        max_retries: int = 3,
    ):
        """
        Initialize GhidraInsight client.
        
        Args:
            base_url: Base URL of GhidraInsight server
            api_key: Optional API key for authentication
            token: Optional JWT token for authentication
            timeout: Request timeout in seconds
            max_retries: Maximum number of retries for failed requests
            
        Raises:
            ValidationError: If parameters are invalid
        """
        if not base_url or not isinstance(base_url, str):
            raise ValidationError("base_url must be a valid URL string")
        
        if timeout < 1:
            raise ValidationError("timeout must be at least 1 second")
        
        if max_retries < 0:
            raise ValidationError("max_retries must be non-negative")
        
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.token = token
        self.timeout = timeout
        self.max_retries = max_retries
        
        self._session = None
        logger.info(f"GhidraInsight client initialized: {self.base_url}")
    
    async def initialize(self):
        """Initialize HTTP session (call before making requests)."""
        try:
            import aiohttp
            
            headers = {"User-Agent": "GhidraInsight-Client/1.0"}
            
            if self.api_key:
                headers["X-API-Key"] = self.api_key
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
            
            self._session = aiohttp.ClientSession(
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            )
            logger.debug("HTTP session initialized")
        except ImportError:
            raise ClientError("aiohttp is required. Install with: pip install aiohttp")
    
    async def close(self):
        """Close HTTP session."""
        if self._session:
            await self._session.close()
            self._session = None
            logger.debug("HTTP session closed")
    
    async def analyze_binary(
        self,
        binary_path: str,
        features: Optional[List[str]] = None,
    ) -> AnalysisResult:
        """
        Analyze a binary file.
        
        Args:
            binary_path: Path to binary file
            features: List of features to analyze (crypto, taint, vulnerability)
            
        Returns:
            AnalysisResult with findings
            
        Raises:
            ValidationError: If parameters are invalid
            ConnectionError: If connection fails
        """
        if not binary_path or not isinstance(binary_path, str):
            raise ValidationError("binary_path must be a valid file path")
        
        features = features or ["crypto", "taint", "vulnerability"]
        
        if not all(isinstance(f, str) for f in features):
            raise ValidationError("features must be a list of strings")
        
        try:
            payload = {
                "binary_path": binary_path,
                "features": features,
            }
            
            response = await self._request("POST", "/api/analyze", json=payload)
            
            result = AnalysisResult(
                binary_name=binary_path,
                analysis_type="binary",
                findings=response.get("findings", []),
                confidence=response.get("confidence", 0.0),
                duration_ms=response.get("duration_ms", 0),
                timestamp=response.get("timestamp", ""),
            )
            
            logger.info(f"Binary analysis completed: {binary_path}")
            return result
        except Exception as e:
            logger.error(f"Binary analysis failed: {e}")
            raise
    
    async def analyze_function(
        self,
        binary_path: str,
        function_address: str,
    ) -> AnalysisResult:
        """
        Analyze a specific function.
        
        Args:
            binary_path: Path to binary file
            function_address: Function address in hex format
            
        Returns:
            AnalysisResult with findings
        """
        if not function_address or not isinstance(function_address, str):
            raise ValidationError("function_address must be a valid hex address")
        
        try:
            response = await self._request(
                "GET",
                f"/api/function/{function_address}",
                params={"binary": binary_path},
            )
            
            result = AnalysisResult(
                binary_name=binary_path,
                analysis_type="function",
                findings=response.get("findings", []),
                confidence=response.get("confidence", 0.0),
                duration_ms=response.get("duration_ms", 0),
                timestamp=response.get("timestamp", ""),
            )
            
            logger.info(f"Function analysis completed: {function_address}")
            return result
        except Exception as e:
            logger.error(f"Function analysis failed: {e}")
            raise
    
    async def taint_analysis(
        self,
        binary_path: str,
        source: str,
        sink: str,
    ) -> AnalysisResult:
        """
        Perform taint analysis from source to sink.
        
        Args:
            binary_path: Path to binary file
            source: Source location/function
            sink: Sink location/function
            
        Returns:
            AnalysisResult with taint flow paths
        """
        if not source or not sink:
            raise ValidationError("source and sink must be provided")
        
        try:
            payload = {
                "binary": binary_path,
                "source": source,
                "sink": sink,
            }
            
            response = await self._request("POST", "/api/taint", json=payload)
            
            result = AnalysisResult(
                binary_name=binary_path,
                analysis_type="taint",
                findings=response.get("paths", []),
                confidence=response.get("confidence", 0.0),
                duration_ms=response.get("duration_ms", 0),
                timestamp=response.get("timestamp", ""),
            )
            
            logger.info(f"Taint analysis completed: {source} -> {sink}")
            return result
        except Exception as e:
            logger.error(f"Taint analysis failed: {e}")
            raise
    
    async def get_status(self) -> Dict[str, Any]:
        """
        Get server status and health information.
        
        Returns:
            Status dictionary
        """
        try:
            response = await self._request("GET", "/api/status")
            logger.debug("Status retrieved successfully")
            return response
        except Exception as e:
            logger.error(f"Status check failed: {e}")
            raise
    
    async def _request(
        self,
        method: str,
        endpoint: str,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Make HTTP request with retry logic.
        
        Args:
            method: HTTP method
            endpoint: API endpoint
            **kwargs: Additional arguments for request
            
        Returns:
            JSON response
            
        Raises:
            ConnectionError: If request fails
            TimeoutError: If request times out
        """
        if not self._session:
            raise ClientError("Client not initialized. Call await client.initialize()")
        
        url = f"{self.base_url}{endpoint}"
        
        for attempt in range(self.max_retries + 1):
            try:
                async with self._session.request(method, url, **kwargs) as response:
                    if response.status == 200:
                        return await response.json()
                    elif response.status == 401:
                        raise ClientError("Unauthorized: check API key/token")
                    elif response.status == 404:
                        raise ClientError(f"Not found: {endpoint}")
                    elif response.status >= 500:
                        if attempt < self.max_retries:
                            await asyncio.sleep(2 ** attempt)
                            continue
                        raise ConnectionError(f"Server error: {response.status}")
                    else:
                        raise ClientError(f"Request failed: {response.status}")
            except asyncio.TimeoutError:
                raise TimeoutError(f"Request timeout after {self.timeout}s")
            except ConnectionError as e:
                if attempt == self.max_retries:
                    raise
                logger.warning(f"Request failed (attempt {attempt + 1}), retrying...")
                await asyncio.sleep(2 ** attempt)
        
        raise ConnectionError("Max retries exceeded")

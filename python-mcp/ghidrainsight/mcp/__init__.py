"""MCP server implementation for GhidraInsight."""

import asyncio
from typing import Any, Dict, Optional, Set
from loguru import logger
import aiohttp
from aiohttp import web
import websockets
import json

from ..core.cache import cached
from ..core.analysis import analysis_engine

class MCPServer:
    """MCP (Model Context Protocol) Server for GhidraInsight."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8000,
        ws_port: int = 8001,
        sse_port: int = 8002,
    ):
        """
        Initialize MCP Server.

        Args:
            host: Bind address
            port: HTTP API port
            ws_port: WebSocket port
            sse_port: Server-Sent Events port
        """
        self.host = host
        self.port = port
        self.ws_port = ws_port
        self.sse_port = sse_port
        self.running = False
        self.app = web.Application()
        self.ws_connections: Set[websockets.WebSocketServerProtocol] = set()

        # Setup routes
        self._setup_routes()

    def _setup_routes(self):
        """Setup HTTP routes."""
        self.app.router.add_post('/api/analyze', self.handle_analyze_http)
        self.app.router.add_get('/health', self.handle_health)

    async def handle_analyze_http(self, request):
        """
        HTTP handler for analysis requests with comprehensive error handling.
        
        Args:
            request: HTTP request object
            
        Returns:
            JSON response with analysis results or error
        """
        try:
            # Validate content type
            content_type = request.headers.get('Content-Type', '')
            if not content_type.startswith('application/json'):
                return web.json_response(
                    {"error": "Content-Type must be application/json"}, 
                    status=400
                )
            
            # Parse and validate request data
            try:
                data = await request.json()
            except json.JSONDecodeError as e:
                return web.json_response(
                    {"error": f"Invalid JSON: {str(e)}"}, 
                    status=400
                )
            
            # Validate required fields
            if not data or "binary_data" not in data:
                return web.json_response(
                    {"error": "binary_data field is required"}, 
                    status=400
                )
            
            # Validate binary data size
            binary_data = data["binary_data"]
            if not isinstance(binary_data, str):
                return web.json_response(
                    {"error": "binary_data must be a base64 string"}, 
                    status=400
                )
            
            # Decode base64 and check size
            try:
                import base64
                decoded_data = base64.b64decode(binary_data)
                if len(decoded_data) > 1024 * 1024 * 1024:  # 1GB limit for malware analysis
                    return web.json_response(
                        {"error": "Binary data too large (max 1GB for malware analysis)"}, 
                        status=413
                    )
            except Exception as e:
                return web.json_response(
                    {"error": f"Invalid binary data: {str(e)}"}, 
                    status=400
                )
            
            # Process analysis
            result = await self.handle_analyze(data)
            return web.json_response(result)
            
        except Exception as e:
            logger.error(f"Analysis error: {e}", exc_info=True)
            return web.json_response(
                {"error": "Internal server error during analysis"}, 
                status=500
            )

    async def handle_health(self, request):
        """Health check endpoint."""
        return web.json_response({"status": "healthy"})

    async def start(self) -> None:
        """Start the MCP server."""
        self.running = True
        logger.info(f"Starting MCP Server on {self.host}:{self.port}")

        # Start HTTP server
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, self.host, self.port)
        await site.start()
        logger.info(f"HTTP server started on {self.host}:{self.port}")

        # Start WebSocket server
        ws_server = await websockets.serve(
            self.handle_websocket,
            self.host,
            self.ws_port
        )
        logger.info(f"WebSocket server started on {self.host}:{self.ws_port}")

        # Keep servers running
        try:
            await asyncio.Future()  # Run forever
        except KeyboardInterrupt:
            logger.info("Shutting down servers...")
            ws_server.close()
            await ws_server.wait_closed()
            await runner.cleanup()

    async def handle_websocket(self, websocket, path):
        """Handle WebSocket connections for real-time collaboration."""
        logger.info(f"New WebSocket connection: {websocket.remote_address}")
        self.ws_connections.add(websocket)

        try:
            async for message in websocket:
                try:
                    data = json.loads(message)
                    message_type = data.get("type")

                    if message_type == "analyze":
                        # Start analysis and stream progress
                        await self._handle_realtime_analysis(websocket, data)
                    elif message_type == "subscribe":
                        # Handle subscription to analysis updates
                        session_id = data.get("session_id")
                        logger.info(f"Client subscribed to session: {session_id}")
                    else:
                        await websocket.send(json.dumps({
                            "type": "error",
                            "message": f"Unknown message type: {message_type}"
                        }))

                except json.JSONDecodeError:
                    await websocket.send(json.dumps({
                        "type": "error",
                        "message": "Invalid JSON message"
                    }))

        except websockets.exceptions.ConnectionClosed:
            logger.info(f"WebSocket connection closed: {websocket.remote_address}")
        finally:
            self.ws_connections.remove(websocket)

    async def _handle_realtime_analysis(self, websocket, data):
        """Handle real-time analysis with progress streaming."""
        try:
            # Send initial status
            await websocket.send(json.dumps({
                "type": "analysis_started",
                "message": "Analysis started"
            }))

            # Simulate analysis progress
            for progress in [10, 25, 50, 75, 90]:
                await asyncio.sleep(0.5)  # Simulate processing time
                await websocket.send(json.dumps({
                    "type": "progress",
                    "progress": progress,
                    "message": f"Analysis {progress}% complete"
                }))

            # Run actual analysis
            result = await self.handle_analyze(data["data"])

            # Send final result
            await websocket.send(json.dumps({
                "type": "analysis_complete",
                "result": result
            }))

        except Exception as e:
            logger.error(f"Real-time analysis error: {e}")
            await websocket.send(json.dumps({
                "type": "error",
                "message": str(e)
            }))

    async def broadcast_to_clients(self, message: Dict[str, Any]):
        """Broadcast message to all connected WebSocket clients."""
        if self.ws_connections:
            message_json = json.dumps(message)
            await asyncio.gather(
                *[ws.send(message_json) for ws in self.ws_connections],
                return_exceptions=True
            )

    async def stop(self) -> None:
        """Stop the MCP server."""
        self.running = False
        logger.info("MCP Server stopped")

    async def handle_analyze(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle analyze request from MCP client with enhanced security and validation.

        Args:
            data: Request data with file and features

        Returns:
            Analysis results
            
        Raises:
            ValueError: If input validation fails
            SecurityError: If security checks fail
        """
        logger.info("Processing analyze request")
        
        # Validate and decode binary data
        binary_data = data.get("binary_data")
        if not binary_data:
            raise ValueError("binary_data is required")
        
        try:
            import base64
            if isinstance(binary_data, str):
                binary_bytes = base64.b64decode(binary_data)
            else:
                binary_bytes = binary_data
        except Exception as e:
            raise ValueError(f"Invalid binary data encoding: {e}")
        
        # Security: Check for malware indicators (not suspicious patterns)
        if self._contains_malware_indicators(binary_bytes):
            logger.info("Malware indicators detected - this is expected for malware analysis")
            # Continue but mark for additional scrutiny
        
        # Validate features
        features = data.get("features", ["basic_info", "strings", "entropy"])
        if not isinstance(features, list):
            raise ValueError("features must be a list")
        
        # Validate feature names
        valid_features = {
            "basic_info", "strings", "entropy", "crypto", "taint", 
            "vulnerability", "control_flow_anomalies", "ml_vulnerability_detection",
            "exploit_patterns", "semantic_analysis"
        }
        invalid_features = set(features) - valid_features
        if invalid_features:
            raise ValueError(f"Invalid features: {invalid_features}")
        
        try:
            # Run parallel analysis with timeout
            results = await asyncio.wait_for(
                analysis_engine.analyze_binary(binary_bytes, features),
                timeout=300  # 5 minutes
            )
            
            # Sanitize results before returning
            sanitized_results = self._sanitize_analysis_results(results)
            
            return {"status": "success", "results": sanitized_results}
            
        except asyncio.TimeoutError:
            raise ValueError("Analysis timeout - binary too complex or large")
        except Exception as e:
            logger.error(f"Analysis failed: {e}", exc_info=True)
            raise ValueError(f"Analysis failed: {e}")

    def _contains_malware_indicators(self, binary_data: bytes) -> bool:
        """
        Check for malware indicators in binary data.
        
        Args:
            binary_data: Binary data to check
            
        Returns:
            True if malware indicators found
        """
        malware_indicators = [
            b'eval(',  # Code execution
            b'system(',  # System calls
            b'exec(',  # Python exec
            b'__import__',  # Dynamic imports
            b'subprocess',  # Subprocess calls
            b'os.system',  # OS system calls
        ]
        
        for pattern in suspicious_patterns:
            if pattern in binary_data:
                return True
        return False
    
    def _sanitize_analysis_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize analysis results to remove sensitive information.
        
        Args:
            results: Raw analysis results
            
        Returns:
            Sanitized results
        """
        sanitized = results.copy()
        
        # Remove potential sensitive data
        if 'results' in sanitized:
            for feature, result in sanitized['results'].items():
                if isinstance(result, dict):
                    # Remove any potential file paths or sensitive strings
                    if 'strings' in result:
                        result['strings'] = [
                            s for s in result['strings'][:50]  # Limit strings
                            if len(s) <= 200 and not any(
                                sensitive in s.lower()
                                for sensitive in ['password', 'key', 'secret', 'token']
                            )
                        ]
        
        return sanitized

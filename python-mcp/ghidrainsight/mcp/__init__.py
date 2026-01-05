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
        """HTTP handler for analysis requests."""
        try:
            data = await request.json()
            result = await self.handle_analyze(data)
            return web.json_response(result)
        except Exception as e:
            logger.error(f"Analysis error: {e}")
            return web.json_response({"error": str(e)}, status=500)

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

    @cached
    async def handle_analyze(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle analyze request from MCP client.

        Args:
            data: Request data with file and features

        Returns:
            Analysis results
        """
        logger.info("Processing analyze request")

        binary_data = data.get("binary_data")
        if not binary_data:
            raise ValueError("binary_data is required")

        features = data.get("features", ["basic_info", "strings", "entropy"])

        # Run parallel analysis
        results = await analysis_engine.analyze_binary(binary_data, features)

        return {"status": "success", "results": results}

    async def handle_query(self, query: str) -> str:
        """
        Handle AI query.

        Args:
            query: Natural language query

        Returns:
            AI-generated response
        """
        logger.info(f"Processing query: {query}")
        # AI processing here
        return "Response"

package com.ghidrainsight.mcp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ghidrainsight.core.GhidraInsightCore;
import java.net.ServerSocket;
import java.io.*;
import java.util.concurrent.*;

/**
 * MCP (Model Context Protocol) Server for GhidraInsight.
 * Provides WebSocket, SSE, and HTTP REST transports.
 * 
 * Transport layers:
 * - HTTP REST API: http://localhost:8000/api/*
 * - WebSocket: ws://localhost:8001
 * - Server-Sent Events (SSE): http://localhost:8002/events
 */
public class MCPServer {
    private static final Logger logger = LoggerFactory.getLogger(MCPServer.class);
    
    private static final int HTTP_PORT = 8000;
    private static final int WS_PORT = 8001;
    private static final int SSE_PORT = 8002;
    private static final int THREAD_POOL_SIZE = 10;
    
    private final GhidraInsightCore core;
    private final ExecutorService executorService;
    private final ConcurrentHashMap<String, WebSocketHandler> wsConnections;
    private final ConcurrentHashMap<String, SSEClient> sseClients;
    
    private volatile boolean running = false;
    private ServerSocket httpServer;
    private ServerSocket wsServer;
    private ServerSocket sseServer;
    
    /**
     * Initialize MCP Server with analysis core.
     *
     * @param core the analysis core engine
     */
    public MCPServer(GhidraInsightCore core) {
        this.core = core;
        this.executorService = Executors.newFixedThreadPool(THREAD_POOL_SIZE);
        this.wsConnections = new ConcurrentHashMap<>();
        this.sseClients = new ConcurrentHashMap<>();
        logger.debug("MCPServer initialized");
    }
    
    /**
     * Start the MCP server with all transports.
     */
    public synchronized void start() {
        if (running) {
            logger.warn("MCP server is already running");
            return;
        }
        
        try {
            logger.info("Starting MCP server with three transports...");
            
            // Start HTTP REST API transport
            startHTTPTransport();
            
            // Start WebSocket transport
            startWebSocketTransport();
            
            // Start SSE transport
            startSSETransport();
            
            running = true;
            logger.info("MCP server started successfully on ports {}, {}, {}",
                    HTTP_PORT, WS_PORT, SSE_PORT);
        } catch (IOException e) {
            logger.error("Failed to start MCP server", e);
            running = false;
            throw new RuntimeException("Server startup failed", e);
        }
    }
    
    /**
     * Start HTTP REST API transport.
     */
    private void startHTTPTransport() throws IOException {
        try {
            httpServer = new ServerSocket(HTTP_PORT);
            
            executorService.execute(() -> {
                while (running) {
                    try {
                        var client = httpServer.accept();
                        executorService.execute(() -> handleHTTPRequest(client));
                    } catch (IOException e) {
                        if (running) {
                            logger.debug("HTTP server error: {}", e.getMessage());
                        }
                    }
                }
            });
            
            logger.info("HTTP REST API transport started on port {}", HTTP_PORT);
        } catch (IOException e) {
            logger.error("Failed to start HTTP transport on port {}", HTTP_PORT, e);
            throw e;
        }
    }
    
    /**
     * Start WebSocket transport.
     */
    private void startWebSocketTransport() throws IOException {
        try {
            wsServer = new ServerSocket(WS_PORT);
            
            executorService.execute(() -> {
                while (running) {
                    try {
                        var client = wsServer.accept();
                        executorService.execute(() -> handleWebSocketConnection(client));
                    } catch (IOException e) {
                        if (running) {
                            logger.debug("WebSocket server error: {}", e.getMessage());
                        }
                    }
                }
            });
            
            logger.info("WebSocket transport started on port {}", WS_PORT);
        } catch (IOException e) {
            logger.error("Failed to start WebSocket transport on port {}", WS_PORT, e);
            throw e;
        }
    }
    
    /**
     * Start Server-Sent Events (SSE) transport.
     */
    private void startSSETransport() throws IOException {
        try {
            sseServer = new ServerSocket(SSE_PORT);
            
            executorService.execute(() -> {
                while (running) {
                    try {
                        var client = sseServer.accept();
                        executorService.execute(() -> handleSSEConnection(client));
                    } catch (IOException e) {
                        if (running) {
                            logger.debug("SSE server error: {}", e.getMessage());
                        }
                    }
                }
            });
            
            logger.info("SSE transport started on port {}", SSE_PORT);
        } catch (IOException e) {
            logger.error("Failed to start SSE transport on port {}", SSE_PORT, e);
            throw e;
        }
    }
    
    /**
     * Handle incoming HTTP request.
     */
    private void handleHTTPRequest(java.net.Socket client) {
        try {
            var in = new BufferedReader(new InputStreamReader(client.getInputStream()));
            var out = new PrintWriter(client.getOutputStream(), true);
            
            String requestLine = in.readLine();
            if (requestLine == null) {
                client.close();
                return;
            }
            
            String[] parts = requestLine.split(" ");
            String method = parts[0];
            String path = parts.length > 1 ? parts[1] : "/";
            
            // Route to appropriate handler
            if (path.startsWith("/api/analyze")) {
                handleAnalysisRequest(method, out);
            } else if (path.startsWith("/api/status")) {
                handleStatusRequest(out);
            } else {
                sendHTTPResponse(out, 404, "Not Found");
            }
            
            client.close();
        } catch (IOException e) {
            logger.error("HTTP request handling failed", e);
        }
    }
    
    /**
     * Handle WebSocket connection.
     */
    private void handleWebSocketConnection(java.net.Socket client) {
        try {
            String connectionId = "ws-" + System.nanoTime();
            WebSocketHandler handler = new WebSocketHandler(client, core, connectionId);
            wsConnections.put(connectionId, handler);
            
            handler.handleConnection();
            
            wsConnections.remove(connectionId);
            logger.debug("WebSocket connection closed: {}", connectionId);
        } catch (Exception e) {
            logger.error("WebSocket connection error", e);
        }
    }
    
    /**
     * Handle SSE (Server-Sent Events) connection.
     */
    private void handleSSEConnection(java.net.Socket client) {
        try {
            String clientId = "sse-" + System.nanoTime();
            SSEClient sseClient = new SSEClient(client, core, clientId);
            sseClients.put(clientId, sseClient);
            
            sseClient.handleConnection();
            
            sseClients.remove(clientId);
            logger.debug("SSE connection closed: {}", clientId);
        } catch (Exception e) {
            logger.error("SSE connection error", e);
        }
    }
    
    /**
     * Handle analysis API request.
     */
    private void handleAnalysisRequest(String method, PrintWriter out) {
        if ("POST".equals(method)) {
            // TODO: Implement analysis request handling
            sendHTTPResponse(out, 200, "{\"status\": \"analysis_queued\"}");
        } else {
            sendHTTPResponse(out, 405, "Method Not Allowed");
        }
    }
    
    /**
     * Handle status API request.
     */
    private void handleStatusRequest(PrintWriter out) {
        String status = String.format(
            "{\"status\": \"healthy\", \"version\": \"1.0.0\", \"uptime\": %d}",
            System.currentTimeMillis()
        );
        sendHTTPResponse(out, 200, status);
    }
    
    /**
     * Send HTTP response.
     */
    private void sendHTTPResponse(PrintWriter out, int statusCode, String body) {
        out.println("HTTP/1.1 " + statusCode + " OK");
        out.println("Content-Type: application/json");
        out.println("Content-Length: " + body.length());
        out.println("Connection: close");
        out.println();
        out.println(body);
        out.flush();
    }
    
    /**
     * Shutdown the MCP server and all transports.
     */
    public synchronized void shutdown() {
        if (!running) {
            logger.warn("MCP server is not running");
            return;
        }
        
        try {
            logger.info("Shutting down MCP server...");
            running = false;
            
            // Close all WebSocket connections
            wsConnections.forEach((id, handler) -> {
                try {
                    handler.close();
                } catch (Exception e) {
                    logger.error("Error closing WebSocket: {}", id, e);
                }
            });
            
            // Close all SSE clients
            sseClients.forEach((id, client) -> {
                try {
                    client.close();
                } catch (Exception e) {
                    logger.error("Error closing SSE client: {}", id, e);
                }
            });
            
            // Close server sockets
            if (httpServer != null && !httpServer.isClosed()) httpServer.close();
            if (wsServer != null && !wsServer.isClosed()) wsServer.close();
            if (sseServer != null && !sseServer.isClosed()) sseServer.close();
            
            // Shutdown executor service
            executorService.shutdown();
            if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
            
            logger.info("MCP server shut down successfully");
        } catch (Exception e) {
            logger.error("Error during shutdown", e);
        }
    }
    
    /**
     * Check if server is running.
     *
     * @return true if server is active
     */
    public boolean isRunning() {
        return running;
    }
    
    /**
     * Get the core engine.
     *
     * @return the GhidraInsightCore
     */
    public GhidraInsightCore getCore() {
        return core;
    }
    
    /**
     * Get number of active WebSocket connections.
     */
    public int getWebSocketConnectionCount() {
        return wsConnections.size();
    }
    
    /**
     * Get number of active SSE clients.
     */
    public int getSSEClientCount() {
        return sseClients.size();
    }
}

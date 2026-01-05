package com.ghidrainsight.mcp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ghidrainsight.core.GhidraInsightCore;
import java.io.*;
import java.net.Socket;
import java.util.*;

/**
 * WebSocket connection handler for real-time analysis updates.
 */
public class WebSocketHandler {
    private static final Logger logger = LoggerFactory.getLogger(WebSocketHandler.class);
    
    private final Socket socket;
    private final GhidraInsightCore core;
    private final String connectionId;
    private volatile boolean connected = false;
    
    /**
     * Initialize WebSocket handler.
     */
    public WebSocketHandler(Socket socket, GhidraInsightCore core, String connectionId) {
        this.socket = socket;
        this.core = core;
        this.connectionId = connectionId;
    }
    
    /**
     * Handle WebSocket connection lifecycle.
     */
    public void handleConnection() {
        try {
            connected = true;
            var in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            var out = new PrintWriter(socket.getOutputStream(), true);
            
            logger.info("WebSocket connected: {}", connectionId);
            
            // Send welcome message
            sendMessage(out, "{\"type\": \"connected\", \"id\": \"" + connectionId + "\"}");
            
            // Read and process messages
            String line;
            while (connected && (line = in.readLine()) != null) {
                processMessage(line, out);
            }
        } catch (IOException e) {
            if (connected) {
                logger.debug("WebSocket error: {}", e.getMessage());
            }
        } finally {
            connected = false;
            try {
                socket.close();
            } catch (IOException e) {
                logger.debug("Error closing socket", e);
            }
        }
    }
    
    /**
     * Process incoming WebSocket message.
     */
    private void processMessage(String message, PrintWriter out) {
        try {
            logger.debug("WebSocket message received: {}", connectionId);
            
            // Echo message back as acknowledgment
            sendMessage(out, "{\"type\": \"ack\", \"received\": \"" + message + "\"}");
        } catch (Exception e) {
            logger.error("Error processing WebSocket message", e);
        }
    }
    
    /**
     * Send message through WebSocket.
     */
    private void sendMessage(PrintWriter out, String message) {
        out.println(message);
        out.flush();
    }
    
    /**
     * Close WebSocket connection.
     */
    public void close() throws IOException {
        connected = false;
        socket.close();
    }
}
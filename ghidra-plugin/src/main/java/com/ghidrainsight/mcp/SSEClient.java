package com.ghidrainsight.mcp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ghidrainsight.core.GhidraInsightCore;
import java.io.*;
import java.net.Socket;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Server-Sent Events (SSE) client handler for streaming updates.
 */
public class SSEClient {
    private static final Logger logger = LoggerFactory.getLogger(SSEClient.class);
    
    private final Socket socket;
    private final GhidraInsightCore core;
    private final String clientId;
    private volatile boolean connected = false;
    
    /**
     * Initialize SSE client handler.
     */
    public SSEClient(Socket socket, GhidraInsightCore core, String clientId) {
        this.socket = socket;
        this.core = core;
        this.clientId = clientId;
    }
    
    /**
     * Handle SSE connection lifecycle.
     */
    public void handleConnection() {
        try {
            connected = true;
            var out = new PrintWriter(socket.getOutputStream(), true);
            
            logger.info("SSE client connected: {}", clientId);
            
            // Send SSE headers
            sendSSEHeaders(out);
            
            // Send initial connection event
            sendSSEEvent(out, "connected", "{\"client_id\": \"" + clientId + "\"}");
            
            // Keep connection alive and send periodic heartbeat
            while (connected) {
                sendSSEEvent(out, "heartbeat", "{\"timestamp\": \"" + getCurrentTimestamp() + "\"}");
                Thread.sleep(30000); // Send heartbeat every 30 seconds
            }
        } catch (InterruptedException e) {
            if (connected) {
                logger.debug("SSE connection interrupted");
            }
        } catch (IOException e) {
            if (connected) {
                logger.debug("SSE I/O error: {}", e.getMessage());
            }
        } finally {
            connected = false;
            try {
                socket.close();
            } catch (IOException e) {
                logger.debug("Error closing SSE socket", e);
            }
        }
    }
    
    /**
     * Send SSE HTTP headers.
     */
    private void sendSSEHeaders(PrintWriter out) {
        out.println("HTTP/1.1 200 OK");
        out.println("Content-Type: text/event-stream");
        out.println("Cache-Control: no-cache");
        out.println("Connection: keep-alive");
        out.println("Access-Control-Allow-Origin: *");
        out.println();
        out.flush();
    }
    
    /**
     * Send SSE event.
     */
    private void sendSSEEvent(PrintWriter out, String eventType, String data) {
        out.println("event: " + eventType);
        out.println("data: " + data);
        out.println();
        out.flush();
    }
    
    /**
     * Send analysis progress event.
     */
    public void sendProgressEvent(String binaryName, int progress, String status) {
        if (!connected) return;
        
        try {
            var out = new PrintWriter(socket.getOutputStream(), true);
            String data = String.format(
                "{\"binary\": \"%s\", \"progress\": %d, \"status\": \"%s\"}",
                binaryName, progress, status
            );
            sendSSEEvent(out, "progress", data);
        } catch (IOException e) {
            logger.error("Error sending progress event", e);
        }
    }
    
    /**
     * Send analysis results event.
     */
    public void sendResultsEvent(String binaryName, String results) {
        if (!connected) return;
        
        try {
            var out = new PrintWriter(socket.getOutputStream(), true);
            String data = String.format(
                "{\"binary\": \"%s\", \"results\": %s}",
                binaryName, results
            );
            sendSSEEvent(out, "results", data);
        } catch (IOException e) {
            logger.error("Error sending results event", e);
        }
    }
    
    /**
     * Send error event.
     */
    public void sendErrorEvent(String errorMessage) {
        if (!connected) return;
        
        try {
            var out = new PrintWriter(socket.getOutputStream(), true);
            String data = String.format("{\"error\": \"%s\"}", errorMessage);
            sendSSEEvent(out, "error", data);
        } catch (IOException e) {
            logger.error("Error sending error event", e);
        }
    }
    
    /**
     * Get current ISO timestamp.
     */
    private String getCurrentTimestamp() {
        return LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
    }
    
    /**
     * Close SSE connection.
     */
    public void close() throws IOException {
        connected = false;
        socket.close();
    }
}
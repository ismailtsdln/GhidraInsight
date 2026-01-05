package com.ghidrainsight;

import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.AddressSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ghidrainsight.core.GhidraInsightCore;
import com.ghidrainsight.mcp.MCPServer;

/**
 * GhidraInsight: AI-driven reverse engineering plugin for Ghidra.
 *
 * This plugin provides:
 * - Advanced binary analysis (crypto detection, taint analysis)
 * - MCP (Model Context Protocol) server for AI integration
 * - REST API for remote analysis
 * - Web dashboard for interactive exploration
 */
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "com.ghidrainsight",
    name = "GhidraInsight",
    description = "AI-assisted reverse engineering with MCP support",
    servicesProvided = {},
    eventsConsumed = {},
    eventsProduced = {}
)
public class GhidraInsightPlugin extends ProgramPlugin {
    private static final Logger logger = LoggerFactory.getLogger(GhidraInsightPlugin.class);
    
    private GhidraInsightCore core;
    private MCPServer mcpServer;
    
    /**
     * Constructs the GhidraInsight plugin.
     *
     * @param tool the PluginTool to attach to
     */
    public GhidraInsightPlugin(PluginTool tool) {
        super(tool, false, true);
        logger.info("Initializing GhidraInsight plugin v1.0.0");
    }
    
    @Override
    protected void init() {
        super.init();
        try {
            // Initialize core analysis engine
            this.core = new GhidraInsightCore();
            logger.info("Core analysis engine initialized");
            
            // Initialize MCP server
            this.mcpServer = new MCPServer(core);
            this.mcpServer.start();
            logger.info("MCP server started on configured ports");
        } catch (Exception e) {
            logger.error("Failed to initialize GhidraInsight plugin", e);
            throw new RuntimeException("Plugin initialization failed", e);
        }
    }
    
    @Override
    public void dispose() {
        super.dispose();
        if (mcpServer != null) {
            mcpServer.shutdown();
            logger.info("MCP server shut down");
        }
        if (core != null) {
            core.cleanup();
            logger.info("Core analysis engine cleaned up");
        }
    }
    
    /**
     * Get the core analysis engine.
     *
     * @return the GhidraInsightCore instance
     */
    public GhidraInsightCore getCore() {
        return core;
    }
    
    /**
     * Get the MCP server instance.
     *
     * @return the MCPServer instance
     */
    public MCPServer getMCPServer() {
        return mcpServer;
    }
}

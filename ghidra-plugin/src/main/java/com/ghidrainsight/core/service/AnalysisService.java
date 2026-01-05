package com.ghidrainsight.core.service;

import com.fasterxml.jackson.databind.JsonNode;
import ghidra.program.model.listing.Program;
import java.util.Map;

/**
 * Service interface for overall binary analysis.
 */
public interface AnalysisService {
    
    /**
     * Analyze a Ghidra program with specified features.
     *
     * @param program the Ghidra program to analyze
     * @param features array of feature names (e.g., "crypto", "taint", "vulnerabilities")
     * @return analysis results as JSON
     */
    JsonNode analyze(Program program, String[] features);
    
    /**
     * Analyze a specific function.
     *
     * @param program the program containing the function
     * @param functionAddress the address of the function to analyze
     * @param depth analysis depth (1=shallow, 5=deep)
     * @return function analysis results
     */
    JsonNode analyzeFunction(Program program, long functionAddress, int depth);
    
    /**
     * Get analysis status.
     *
     * @return map of status information
     */
    Map<String, Object> getStatus();
}

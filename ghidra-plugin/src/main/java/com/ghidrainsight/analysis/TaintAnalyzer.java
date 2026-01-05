package com.ghidrainsight.analysis;

import com.fasterxml.jackson.databind.JsonNode;
import ghidra.program.model.listing.Program;

/**
 * Interface for taint analysis (data flow tracking).
 */
public interface TaintAnalyzer {
    
    /**
     * Perform taint analysis from source to sink.
     *
     * @param program the program to analyze
     * @return JSON containing taint flow paths
     */
    JsonNode analyze(Program program);
    
    /**
     * Analyze taint flow between two addresses.
     *
     * @param program the program
     * @param sourceAddress the source address
     * @param sinkAddress the sink address
     * @return taint flow paths
     */
    JsonNode analyzePath(Program program, long sourceAddress, long sinkAddress);
}

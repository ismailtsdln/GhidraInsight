package com.ghidrainsight.analysis;

import com.fasterxml.jackson.databind.JsonNode;
import ghidra.program.model.listing.Program;

/**
 * Interface for cryptographic algorithm detection.
 */
public interface CryptoDetector {
    
    /**
     * Detect cryptographic algorithms in a program.
     *
     * @param program the program to analyze
     * @return JSON containing detected algorithms and their locations
     */
    JsonNode detectCrypto(Program program);
    
    /**
     * Check if a pattern matches known crypto algorithms.
     *
     * @param bytes the bytes to check
     * @return true if crypto pattern detected
     */
    boolean isCryptoPattern(byte[] bytes);
}

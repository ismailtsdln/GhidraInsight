package com.ghidrainsight.core.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import ghidra.program.model.listing.Program;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.inject.Inject;
import com.ghidrainsight.analysis.CryptoDetector;
import com.ghidrainsight.analysis.TaintAnalyzer;
import java.util.HashMap;
import java.util.Map;

/**
 * Implementation of AnalysisService.
 */
public class AnalysisServiceImpl implements AnalysisService {
    private static final Logger logger = LoggerFactory.getLogger(AnalysisServiceImpl.class);
    private static final ObjectMapper mapper = new ObjectMapper();
    
    private final CryptoDetector cryptoDetector;
    private final TaintAnalyzer taintAnalyzer;
    private final VulnerabilityDetector vulnerabilityDetector;
    
    @Inject
    public AnalysisServiceImpl(CryptoDetector cryptoDetector,
                             TaintAnalyzer taintAnalyzer,
                             VulnerabilityDetector vulnerabilityDetector) {
        this.cryptoDetector = cryptoDetector;
        this.taintAnalyzer = taintAnalyzer;
        this.vulnerabilityDetector = vulnerabilityDetector;
    }
    
    @Override
    public JsonNode analyze(Program program, String[] features) {
        ObjectNode result = mapper.createObjectNode();
        
        try {
            for (String feature : features) {
                switch (feature.toLowerCase()) {
                    case "crypto":
                        result.set("crypto", cryptoDetector.detectCrypto(program));
                        break;
                    case "taint":
                        result.set("taint", taintAnalyzer.analyze(program));
                        break;
                    case "vulnerabilities":
                        result.set("vulnerabilities", vulnerabilityDetector.detect(program));
                        break;
                    default:
                        logger.warn("Unknown feature: {}", feature);
                }
            }
            result.put("status", "success");
        } catch (Exception e) {
            logger.error("Analysis failed", e);
            result.put("status", "error");
            result.put("error", e.getMessage());
        }
        
        return result;
    }
    
    @Override
    public JsonNode analyzeFunction(Program program, long functionAddress, int depth) {
        ObjectNode result = mapper.createObjectNode();
        
        try {
            // Function analysis logic
            result.put("address", String.format("0x%x", functionAddress));
            result.put("depth", depth);
            result.put("status", "success");
        } catch (Exception e) {
            logger.error("Function analysis failed", e);
            result.put("status", "error");
            result.put("error", e.getMessage());
        }
        
        return result;
    }
    
    @Override
    public Map<String, Object> getStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("service", "AnalysisService");
        status.put("status", "running");
        status.put("version", "1.0.0");
        return status;
    }
}

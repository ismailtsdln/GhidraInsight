package com.ghidrainsight.core;

import com.google.inject.Guice;
import com.google.inject.Injector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.ghidrainsight.core.service.AnalysisService;
import com.ghidrainsight.core.service.VulnerabilityDetector;
import com.ghidrainsight.analysis.CryptoDetector;
import com.ghidrainsight.analysis.TaintAnalyzer;

/**
 * Core analysis engine for GhidraInsight.
 * Manages all analysis services and coordinates plugin functionality.
 */
public class GhidraInsightCore {
    private static final Logger logger = LoggerFactory.getLogger(GhidraInsightCore.class);
    
    private final Injector injector;
    private final AnalysisService analysisService;
    private final VulnerabilityDetector vulnerabilityDetector;
    private final CryptoDetector cryptoDetector;
    private final TaintAnalyzer taintAnalyzer;
    
    /**
     * Initialize the core analysis engine with dependency injection.
     */
    public GhidraInsightCore() {
        this.injector = Guice.createInjector(new GhidraInsightModule());
        this.analysisService = injector.getInstance(AnalysisService.class);
        this.vulnerabilityDetector = injector.getInstance(VulnerabilityDetector.class);
        this.cryptoDetector = injector.getInstance(CryptoDetector.class);
        this.taintAnalyzer = injector.getInstance(TaintAnalyzer.class);
        
        logger.info("GhidraInsightCore initialized with all services");
    }
    
    /**
     * Get the analysis service.
     *
     * @return the AnalysisService instance
     */
    public AnalysisService getAnalysisService() {
        return analysisService;
    }
    
    /**
     * Get the vulnerability detector.
     *
     * @return the VulnerabilityDetector instance
     */
    public VulnerabilityDetector getVulnerabilityDetector() {
        return vulnerabilityDetector;
    }
    
    /**
     * Get the crypto detector.
     *
     * @return the CryptoDetector instance
     */
    public CryptoDetector getCryptoDetector() {
        return cryptoDetector;
    }
    
    /**
     * Get the taint analyzer.
     *
     * @return the TaintAnalyzer instance
     */
    public TaintAnalyzer getTaintAnalyzer() {
        return taintAnalyzer;
    }
    
    /**
     * Get the dependency injection container.
     *
     * @return the Guice Injector
     */
    public Injector getInjector() {
        return injector;
    }
    
    /**
     * Cleanup resources.
     */
    public void cleanup() {
        logger.info("Cleaning up GhidraInsightCore resources");
        // Cleanup logic if needed
    }
}

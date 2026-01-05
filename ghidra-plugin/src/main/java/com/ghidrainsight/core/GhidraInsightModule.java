package com.ghidrainsight.core;

import com.google.inject.AbstractModule;
import com.ghidrainsight.core.service.AnalysisService;
import com.ghidrainsight.core.service.AnalysisServiceImpl;
import com.ghidrainsight.core.service.VulnerabilityDetector;
import com.ghidrainsight.core.service.VulnerabilityDetectorImpl;
import com.ghidrainsight.analysis.CryptoDetector;
import com.ghidrainsight.analysis.CryptoDetectorImpl;
import com.ghidrainsight.analysis.TaintAnalyzer;
import com.ghidrainsight.analysis.TaintAnalyzerImpl;

/**
 * Guice dependency injection module for GhidraInsight.
 * Configures bindings for all services and analysis engines.
 */
public class GhidraInsightModule extends AbstractModule {
    
    @Override
    protected void configure() {
        // Service bindings
        bind(AnalysisService.class).to(AnalysisServiceImpl.class);
        bind(VulnerabilityDetector.class).to(VulnerabilityDetectorImpl.class);
        bind(CryptoDetector.class).to(CryptoDetectorImpl.class);
        bind(TaintAnalyzer.class).to(TaintAnalyzerImpl.class);
    }
}

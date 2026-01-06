"""
Example custom analyzer plugin for GhidraInsight.

This demonstrates how to create a custom analysis module.
"""

from ghidrainsight.plugins import BaseAnalyzer, AnalysisResult
from typing import Dict, Any, Optional, List
import time


class ExampleCustomAnalyzer(BaseAnalyzer):
    """
    Example custom analyzer that detects suspicious patterns.
    
    This is a template for creating your own analyzers.
    """
    
    def __init__(self):
        super().__init__(
            name="example_custom_analyzer",
            version="1.0.0"
        )
        self.config = {
            "min_pattern_length": 4,
            "suspicious_threshold": 0.7,
        }
    
    def analyze(self, binary_data: bytes, context: Optional[Dict[str, Any]] = None) -> AnalysisResult:
        """Analyze binary for suspicious patterns."""
        start_time = time.time()
        findings: List[Dict[str, Any]] = []
        
        # Example: Detect suspicious byte patterns
        suspicious_patterns = [
            b"\x90\x90\x90\x90",  # NOP sled
            b"\xCC\xCC\xCC\xCC",  # INT3 breakpoints
            b"\xEB\xFE",          # Infinite loop
        ]
        
        for pattern in suspicious_patterns:
            count = binary_data.count(pattern)
            if count > 0:
                findings.append({
                    "type": "suspicious_pattern",
                    "pattern": pattern.hex(),
                    "count": count,
                    "severity": "medium",
                    "description": f"Found {count} occurrences of suspicious pattern {pattern.hex()}",
                })
        
        # Example: Check entropy
        if len(binary_data) > 0:
            byte_counts = {}
            for byte in binary_data:
                byte_counts[byte] = byte_counts.get(byte, 0) + 1
            
            entropy = 0
            for count in byte_counts.values():
                p = count / len(binary_data)
                if p > 0:
                    entropy -= p * (p ** 0.5)
            
            if entropy > 7.5:  # High entropy threshold
                findings.append({
                    "type": "high_entropy",
                    "entropy": round(entropy, 2),
                    "severity": "low",
                    "description": f"High entropy detected: {entropy:.2f} (possible encryption/compression)",
                })
        
        execution_time = (time.time() - start_time) * 1000
        
        return self._create_result(
            findings=findings,
            metadata={
                "binary_size": len(binary_data),
                "patterns_checked": len(suspicious_patterns),
            },
            execution_time_ms=execution_time,
            confidence=0.85
        )
    
    def validate(self) -> bool:
        """Validate plugin configuration."""
        return (
            self.config.get("min_pattern_length", 0) > 0 and
            self.config.get("suspicious_threshold", 0) > 0
        )

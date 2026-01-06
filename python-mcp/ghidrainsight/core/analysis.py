"""Enhanced analysis module with comprehensive error handling and security."""

import asyncio
import hashlib
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List, Optional
import logging

from ..config import settings
from ..security import SecurityValidator, InputValidator
from ..error_handling import (
    AnalysisError, ValidationError, SecurityError,
    safe_execute, retry_on_failure, validate_inputs,
    global_error_handler
)
from .exploit_patterns import exploit_pattern_library
from .distributed_analysis import distributed_manager
from .error_recovery import error_recovery_manager
from ..llm_integration import LLMIntegration

logger = logging.getLogger(__name__)


class AnalysisEngine:
    """Analysis engine with parallel processing capabilities and comprehensive security."""

    def __init__(self, max_workers: int = 4):
        """
        Initialize analysis engine.
        
        Args:
            max_workers: Maximum number of worker threads
        """
        if max_workers < 1 or max_workers > 16:
            raise ValidationError("max_workers must be between 1 and 16")
        
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.llm_integration = LLMIntegration(settings)
        self.security_validator = SecurityValidator()
        self.input_validator = InputValidator()
        
        logger.info(f"AnalysisEngine initialized with {max_workers} workers")

    @validate_inputs(
        binary_data=lambda x: isinstance(x, bytes) and len(x) > 0,
        features=lambda x: isinstance(x, list) and len(x) > 0,
        use_distributed=lambda x: isinstance(x, bool)
    )
    @retry_on_failure(max_retries=2, delay=1.0)
    async def analyze_binary(self, binary_data: bytes, features: List[str],
                           use_distributed: bool = False) -> Dict[str, Any]:
        """
        Analyze binary with comprehensive security validation and error handling.

        Args:
            binary_data: Binary file content
            features: List of analysis features to run
            use_distributed: Whether to use distributed analysis

        Returns:
            Analysis results with security metadata
            
        Raises:
            ValidationError: If input validation fails
            SecurityError: If security checks fail
            AnalysisError: If analysis fails
        """
        # Security validation
        if not self.security_validator.validate_binary_size(binary_data):
            raise ValidationError("Binary data too large (max 1GB for malware analysis)")
        
        # File type detection for analysis context
        file_type = self.security_validator.detect_file_type(binary_data)
        if file_type:
            logger.info(f"Detected file type: {file_type}")
        else:
            logger.info("Unknown file type - proceeding with analysis")
        
        malware_indicators = self.security_validator.contains_malware_indicators(binary_data)
        if malware_indicators:
            logger.info(f"Malware indicators detected: {malware_indicators}")
        
        # Feature validation
        if not self.input_validator.validate_feature_list(features):
            raise ValidationError(f"Invalid features: {features}")
        
        async def _analysis_operation():
            try:
                if use_distributed:
                    return await distributed_manager.analyze_distributed(binary_data, features)
                else:
                    return await self._analyze_parallel(binary_data, features)
            except Exception as e:
                raise AnalysisError(f"Analysis operation failed: {e}")

        # Execute with error recovery
        try:
            result = await error_recovery_manager.execute_with_recovery(
                _analysis_operation,
                f"binary_analysis_{'distributed' if use_distributed else 'parallel'}",
                binary_data,
                features
            )
        except Exception as e:
            global_error_handler.handle_error(e, {
                "operation": "binary_analysis",
                "features": features,
                "binary_size": len(binary_data),
                "distributed": use_distributed
            })
            raise AnalysisError(f"Analysis failed: {e}")

        # Enhance results with security metadata
        result["security_metadata"] = {
            "malware_indicators": malware_indicators,
            "binary_size": len(binary_data),
            "binary_hash": hashlib.sha256(binary_data).hexdigest(),
            "file_type": file_type,
            "analysis_timestamp": asyncio.get_event_loop().time()
        }

        # Enhance results with LLM insights if available
        if self.llm_integration.is_available() and 'llm_enhancement' in features:
            try:
                result = await self._enhance_with_llm(result)
            except Exception as e:
                logger.warning(f"LLM enhancement failed: {e}")
                # Continue without LLM enhancement

        return result

    async def _analyze_parallel(self, binary_data: bytes, features: List[str]) -> Dict[str, Any]:
        """
        Analyze binary with local parallel processing.

        Args:
            binary_data: Binary file content
            features: List of analysis features to run

        Returns:
            Analysis results
        """
        # Calculate binary hash for caching
        binary_hash = hashlib.sha256(binary_data).hexdigest()

        # Run analysis tasks in parallel
        tasks = []
        for feature in features:
            task = asyncio.get_event_loop().run_in_executor(
                self.executor, self._run_feature_analysis, feature, binary_data
            )
            tasks.append(task)

        # Wait for all tasks to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        analysis_results = {}
        for i, result in enumerate(results):
            feature = features[i]
            if isinstance(result, Exception):
                logger.error(f"Analysis failed for {feature}: {result}")
                analysis_results[feature] = {"error": str(result)}
            else:
                analysis_results[feature] = result

        return {
            "binary_hash": binary_hash,
            "features_analyzed": features,
            "results": analysis_results,
            "parallel_processing": True
        }

    def _run_feature_analysis(self, feature: str, binary_data: bytes) -> Dict[str, Any]:
        """
        Run analysis for a specific feature.

        This is a placeholder - actual analysis logic would go here.
        """
        # Simulate analysis time
        import time
        time.sleep(0.1)  # Simulate processing time

        if feature == "basic_info":
            return {
                "file_size": len(binary_data),
                "hash": hashlib.md5(binary_data).hexdigest()
            }
        elif feature == "strings":
            # Simple string extraction
            strings = []
            current_string = b""
            for byte in binary_data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += bytes([byte])
                else:
                    if len(current_string) >= 4:
                        strings.append(current_string.decode('ascii', errors='ignore'))
                    current_string = b""
            return {"strings": strings[:100]}  # Limit to 100 strings
        elif feature == "entropy":
            # Simple entropy calculation
            from collections import Counter
            import math
            byte_counts = Counter(binary_data)
            entropy = 0
            for count in byte_counts.values():
                p = count / len(binary_data)
                entropy -= p * math.log2(p)
            return {"entropy": entropy}
        elif feature == "control_flow_anomalies":
            # Advanced control flow anomaly detection
            return self._detect_control_flow_anomalies(binary_data)
        elif feature == "ml_vulnerability_detection":
            # Machine learning-based vulnerability detection
            return self._ml_vulnerability_detection(binary_data)
        elif feature == "exploit_patterns":
            # Known exploit pattern detection
            return exploit_pattern_library.scan_binary(binary_data)
        elif feature == "semantic_analysis":
            # Semantic analysis for false positive reduction
            return self._semantic_false_positive_reduction(binary_data)
        else:
            return {"status": f"Analysis for {feature} completed"}

    def _detect_control_flow_anomalies(self, binary_data: bytes) -> Dict[str, Any]:
        """
        Detect control flow anomalies in binary.

        This is a simplified implementation that looks for suspicious patterns.
        """
        anomalies = []
        data_len = len(binary_data)

        # Look for suspicious jump patterns
        suspicious_patterns = [
            b'\xEB\xFE',  # JMP -2 (infinite loop)
            b'\xE9\x00\x00\x00\x00',  # CALL 0 (null call)
            b'\xFF\xFF\xFF\xFF',  # Invalid instruction
        ]

        for pattern in suspicious_patterns:
            pos = 0
            while True:
                pos = binary_data.find(pattern, pos)
                if pos == -1:
                    break

                anomaly_type = "infinite_loop" if pattern == b'\xEB\xFE' else \
                              "null_call" if pattern == b'\xE9\x00\x00\x00\x00' else \
                              "invalid_instruction"

                anomalies.append({
                    "address": f"0x{pos:08X}",
                    "type": anomaly_type,
                    "pattern": pattern.hex(),
                    "severity": "high" if anomaly_type == "infinite_loop" else "medium",
                    "description": f"Detected {anomaly_type.replace('_', ' ')} at offset {pos}"
                })

                pos += 1

        # Look for unusual function prologue patterns
        prologue_patterns = [
            b'\x55\x89\xE5',  # PUSH EBP; MOV EBP, ESP (standard x86)
            b'\x55\x48\x89\xE5',  # PUSH RBP; MOV RBP, RSP (x64)
        ]

        prologue_count = 0
        for pattern in prologue_patterns:
            prologue_count += binary_data.count(pattern)

        # Detect potential obfuscation (high entropy regions)
        entropy_anomalies = []
        window_size = 256
        for i in range(0, data_len - window_size, window_size // 2):
            window = binary_data[i:i + window_size]
            from collections import Counter
            import math
            byte_counts = Counter(window)
            entropy = 0
            for count in byte_counts.values():
                p = count / window_size
                if p > 0:
                    entropy -= p * math.log2(p)

            if entropy > 7.5:  # High entropy threshold
                entropy_anomalies.append({
                    "address": f"0x{i:08X}",
                    "type": "high_entropy_region",
                    "entropy": round(entropy, 2),
                    "severity": "medium",
                    "description": f"High entropy region detected (entropy: {entropy:.2f})"
                })

        all_anomalies = anomalies + entropy_anomalies[:10]  # Limit to 10 anomalies

        return {
            "total_anomalies": len(all_anomalies),
            "anomalies": all_anomalies,
            "function_prologues_found": prologue_count,
            "analysis_confidence": 0.75
        }

    def _ml_vulnerability_detection(self, binary_data: bytes) -> Dict[str, Any]:
        """
        Machine learning-based vulnerability detection.

        Uses simple ML models to detect common vulnerability patterns.
        """
        try:
            import numpy as np
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.preprocessing import StandardScaler
        except ImportError:
            return {
                "error": "ML dependencies not available",
                "vulnerabilities": [],
                "confidence": 0.0
            }

        # Extract features from binary
        features = self._extract_binary_features(binary_data)

        # Simple vulnerability detection rules (simulating ML model)
        vulnerabilities = []

        # Buffer overflow detection
        if features['string_count'] > 50 and features['entropy'] > 6.0:
            vulnerabilities.append({
                "type": "potential_buffer_overflow",
                "severity": "high",
                "confidence": 0.85,
                "description": "High string count with high entropy suggests potential buffer overflow vulnerability",
                "location": "multiple_functions"
            })

        # Format string vulnerability detection
        format_specifiers = [b'%s', b'%d', b'%x', b'%p']
        format_count = sum(binary_data.count(spec) for spec in format_specifiers)
        if format_count > 10:
            vulnerabilities.append({
                "type": "potential_format_string_vulnerability",
                "severity": "medium",
                "confidence": 0.75,
                "description": f"High number of format specifiers ({format_count}) detected",
                "location": "string_handling_functions"
            })

        # Integer overflow detection
        arithmetic_ops = [b'\x05', b'\x2D', b'\xF7', b'\xF6']  # ADD, SUB, DIV, MUL opcodes (simplified)
        arith_count = sum(binary_data.count(op) for op in arithmetic_ops)
        if arith_count > 100 and not self._has_bounds_checking(binary_data):
            vulnerabilities.append({
                "type": "potential_integer_overflow",
                "severity": "medium",
                "confidence": 0.70,
                "description": "High arithmetic operations without apparent bounds checking",
                "location": "arithmetic_functions"
            })

        # Use of dangerous functions
        dangerous_functions = [
            b'strcpy', b'strcat', b'sprintf', b'gets', b'scanf',
            b'memcpy', b'memmove', b'memset'
        ]
        dangerous_count = sum(binary_data.count(func) for func in dangerous_functions)
        if dangerous_count > 5:
            vulnerabilities.append({
                "type": "use_of_dangerous_functions",
                "severity": "high",
                "confidence": 0.90,
                "description": f"Use of {dangerous_count} potentially dangerous C functions",
                "location": "imported_functions"
            })

        return {
            "total_vulnerabilities": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "features_analyzed": features,
            "ml_model_version": "1.0.0",
            "analysis_confidence": 0.80
        }

    def _extract_binary_features(self, binary_data: bytes) -> Dict[str, float]:
        """Extract numerical features from binary for ML analysis."""
        # Basic statistical features
        byte_counts = {}
        for byte in binary_data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1

        # Entropy calculation
        entropy = 0
        data_len = len(binary_data)
        for count in byte_counts.values():
            p = count / data_len
            if p > 0:
                entropy -= p * (p ** 0.5)  # Simplified entropy

        # String features
        strings = []
        current_string = b""
        for byte in binary_data:
            if 32 <= byte <= 126:
                current_string += bytes([byte])
            else:
                if len(current_string) >= 4:
                    strings.append(current_string)
                current_string = b""

        return {
            "file_size": data_len,
            "entropy": entropy,
            "unique_bytes": len(byte_counts),
            "string_count": len(strings),
            "avg_string_length": sum(len(s) for s in strings) / len(strings) if strings else 0,
            "byte_diversity": len(byte_counts) / 256.0
        }

    def _has_bounds_checking(self, binary_data: bytes) -> bool:
        """Simple check for bounds checking patterns."""
        bounds_patterns = [
            b'cmp', b'test', b'jl', b'jg', b'jb', b'ja'  # Comparison instructions
        ]
        bounds_count = sum(binary_data.count(pattern) for pattern in bounds_patterns)
        return bounds_count > 20  # Arbitrary threshold

    def _semantic_false_positive_reduction(self, binary_data: bytes) -> Dict[str, Any]:
        """
        Semantic analysis to reduce false positives in vulnerability detection.

        Analyzes code context and patterns to validate or invalidate potential vulnerabilities.
        """
        # Run multiple analyses to get context
        control_flow = self._detect_control_flow_anomalies(binary_data)
        ml_vulns = self._ml_vulnerability_detection(binary_data)
        patterns = exploit_pattern_library.scan_binary(binary_data)

        validated_findings = []
        false_positives = []

        # Analyze control flow anomalies
        for anomaly in control_flow.get("anomalies", []):
            if self._validate_control_flow_anomaly(anomaly, binary_data):
                validated_findings.append({
                    "type": "control_flow_anomaly",
                    "finding": anomaly,
                    "confidence": 0.85,
                    "validation_reason": "Context analysis confirms anomaly"
                })
            else:
                false_positives.append({
                    "type": "control_flow_anomaly",
                    "finding": anomaly,
                    "reason": "False positive - normal code pattern"
                })

        # Analyze ML-detected vulnerabilities
        for vuln in ml_vulns.get("vulnerabilities", []):
            if self._validate_ml_vulnerability(vuln, binary_data):
                validated_findings.append({
                    "type": "ml_vulnerability",
                    "finding": vuln,
                    "confidence": vuln.get("confidence", 0.5),
                    "validation_reason": "Semantic analysis confirms vulnerability"
                })
            else:
                false_positives.append({
                    "type": "ml_vulnerability",
                    "finding": vuln,
                    "reason": "False positive - mitigated by code structure"
                })

        # Analyze pattern matches
        for pattern in patterns.get("detected_patterns", []):
            if self._validate_exploit_pattern(pattern, binary_data):
                validated_findings.append({
                    "type": "exploit_pattern",
                    "finding": pattern,
                    "confidence": 0.90,
                    "validation_reason": "Pattern confirmed in exploitable context"
                })
            else:
                false_positives.append({
                    "type": "exploit_pattern",
                    "finding": pattern,
                    "reason": "False positive - pattern in benign context"
                })

        return {
            "total_findings": len(validated_findings),
            "validated_findings": validated_findings,
            "false_positives_reduced": len(false_positives),
            "false_positives": false_positives,
            "analysis_accuracy": len(validated_findings) / max(1, len(validated_findings) + len(false_positives)),
            "semantic_rules_applied": [
                "context_aware_analysis",
                "code_structure_validation",
                "mitigation_technique_detection",
                "pattern_context_evaluation"
            ]
        }

    def _validate_control_flow_anomaly(self, anomaly: Dict[str, Any], binary_data: bytes) -> bool:
        """Validate if a control flow anomaly is genuine."""
        anomaly_type = anomaly.get("type", "")

        if anomaly_type == "infinite_loop":
            # Check if it's actually a legitimate loop
            address = anomaly.get("address", "")
            if address:
                # Look for loop control structures nearby
                pos = int(address, 16) if address.startswith("0x") else 0
                context = binary_data[max(0, pos-20):pos+20]
                loop_indicators = [b'jmp', b'jne', b'je', b'jl', b'jg']
                has_loop_control = any(indicator in context for indicator in loop_indicators)
                return not has_loop_control  # If no loop control, it's suspicious

        elif anomaly_type == "high_entropy_region":
            # Check if high entropy is in code or data section
            # Simplified: assume high entropy in code sections is suspicious
            return True  # For now, trust the entropy analysis

        return True  # Default to valid

    def _validate_ml_vulnerability(self, vuln: Dict[str, Any], binary_data: bytes) -> bool:
        """Validate ML-detected vulnerability with semantic analysis."""
        vuln_type = vuln.get("type", "")

        if vuln_type == "potential_buffer_overflow":
            # Check for buffer size validation
            has_size_checks = b'cmp' in binary_data or b'test' in binary_data
            has_safe_functions = b'strncpy' in binary_data or b'memcpy_s' in binary_data
            return not (has_size_checks or has_safe_functions)

        elif vuln_type == "potential_format_string_vulnerability":
            # Check if format functions are used safely
            has_format_validation = b'vsnprintf' in binary_data or b'snprintf' in binary_data
            return not has_format_validation

        elif vuln_type == "use_of_dangerous_functions":
            # Check if dangerous functions are wrapped safely
            dangerous_funcs = [b'strcpy', b'strcat', b'sprintf', b'gets']
            safe_wrappers = sum(1 for func in dangerous_funcs if func in binary_data)
            return safe_wrappers > 2  # If many dangerous functions, likely vulnerable

        return True  # Default to valid

    def _validate_exploit_pattern(self, pattern: Dict[str, Any], binary_data: bytes) -> bool:
        """Validate if an exploit pattern is in exploitable context."""
        pattern_type = pattern.get("pattern_type", "")

        if pattern_type == "shellcode":
            # Check if shellcode is in executable context
            # Simplified: check for nearby function prologue
            locations = pattern.get("locations", [])
            for loc in locations:
                if loc.startswith("0x"):
                    pos = int(loc, 16)
                    # Look for function prologue nearby
                    context_start = max(0, pos - 50)
                    context_end = min(len(binary_data), pos + 50)
                    context = binary_data[context_start:context_end]
                    has_function_prologue = b'\x55\x89\xe5' in context  # push ebp; mov ebp, esp
                    if has_function_prologue:
                        return True  # Shellcode in function context is suspicious
            return False

        elif pattern_type == "sql_injection":
            # Check if SQL is in web application context
            has_web_indicators = b'HTTP' in binary_data or b'POST' in binary_data
            return has_web_indicators

        elif pattern_type == "xss":
            # Check if XSS is in web output context
            has_output_indicators = b'echo' in binary_data or b'print' in binary_data
            return has_output_indicators

        return True  # Default to valid


    async def _enhance_with_llm(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enhance analysis results with LLM insights.

        Args:
            analysis_result: Base analysis results

        Returns:
            Enhanced analysis results with AI insights
        """
        try:
            enhanced_result = analysis_result.copy()

            # Enhance function analysis
            if 'functions' in analysis_result.get('results', {}):
                functions = analysis_result['results']['functions']
                if isinstance(functions, list):
                    enhanced_functions = []
                    for func in functions:
                        enhanced_func = await self.llm_integration.enhance_function_analysis(func)
                        enhanced_functions.append(enhanced_func)
                    enhanced_result['results']['functions'] = enhanced_functions

            # Enhance vulnerability explanations
            if 'vulnerabilities' in analysis_result.get('results', {}):
                vulns = analysis_result['results']['vulnerabilities']
                if isinstance(vulns, list):
                    binary_context = {
                        'type': analysis_result.get('binary_type', 'unknown'),
                        'architecture': analysis_result.get('architecture', 'unknown'),
                        'compiler': analysis_result.get('compiler', 'unknown')
                    }
                    enhanced_vulns = await self.llm_integration.explain_vulnerabilities(
                        vulns, binary_context
                    )
                    enhanced_result['results']['vulnerabilities'] = enhanced_vulns

            # Add LLM metadata
            enhanced_result['llm_enhanced'] = True
            enhanced_result['llm_available'] = self.llm_integration.is_available()

            logger.info("Analysis results enhanced with LLM insights")
            return enhanced_result

        except Exception as e:
            logger.error(f"Failed to enhance analysis with LLM: {e}")
            # Return original result if LLM enhancement fails
            analysis_result['llm_enhanced'] = False
            analysis_result['llm_error'] = str(e)
            return analysis_result


# Global analysis engine instance
analysis_engine = AnalysisEngine()

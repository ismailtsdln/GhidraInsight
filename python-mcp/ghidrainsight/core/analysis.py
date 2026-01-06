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
from .real_analysis import real_analysis_engine
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
                    return await distributed_manager.analyze_distributed_chunks(binary_data, features)
                else:
                    # Use real analysis engine instead of placeholder
                    return real_analysis_engine.analyze_binary(binary_data, features)
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
            logger.error(f"Analysis failed: {e}")
            # Fallback to direct analysis without error recovery
            result = real_analysis_engine.analyze_binary(binary_data, features)

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
                logger.warning(f"LLM enhancement for real analysis results failed: {e}")

        return result

    async def _enhance_with_llm(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enhance real analysis results with LLM insights.
        """
        try:
            enhanced_result = analysis_result.copy()

            # Enhance function analysis
            if 'functions' in analysis_result:
                functions = analysis_result['functions']
                if isinstance(functions, list):
                    enhanced_functions = []
                    for func in functions:
                        # Simple enhancement without LLM dependency
                        enhanced_func = func.copy()
                        if 'instructions' in func and len(func['instructions']) > 0:
                            enhanced_func['complexity'] = "medium" if len(func['instructions']) > 10 else "low"
                        enhanced_functions.append(enhanced_func)
                    enhanced_result['functions'] = enhanced_functions

            # Add metadata
            enhanced_result['llm_enhanced'] = False  # Disabled for now
            enhanced_result['analysis_type'] = "real_binary_analysis"

            logger.info("Analysis results processed")
            return enhanced_result

        except Exception as e:
            logger.error(f"Failed to enhance analysis: {e}")
            analysis_result['llm_enhanced'] = False
            analysis_result['llm_error'] = str(e)
            return analysis_result


# Global analysis engine instance
analysis_engine = AnalysisEngine()

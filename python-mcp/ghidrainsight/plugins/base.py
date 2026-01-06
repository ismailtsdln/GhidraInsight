"""Base classes for GhidraInsight plugins."""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime


@dataclass
class AnalysisResult:
    """Result from a plugin analysis."""
    plugin_name: str
    findings: List[Dict[str, Any]]
    metadata: Dict[str, Any]
    execution_time_ms: float
    timestamp: str
    confidence: float = 1.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "plugin_name": self.plugin_name,
            "findings": self.findings,
            "metadata": self.metadata,
            "execution_time_ms": self.execution_time_ms,
            "timestamp": self.timestamp,
            "confidence": self.confidence,
        }


class BaseAnalyzer(ABC):
    """
    Base class for custom analysis plugins.
    
    Subclass this to create custom analysis modules.
    """
    
    def __init__(self, name: str, version: str = "1.0.0"):
        """
        Initialize plugin.
        
        Args:
            name: Plugin name (must be unique)
            version: Plugin version
        """
        self.name = name
        self.version = version
        self.enabled = True
        self.config: Dict[str, Any] = {}
    
    @abstractmethod
    def analyze(self, binary_data: bytes, context: Optional[Dict[str, Any]] = None) -> AnalysisResult:
        """
        Perform analysis on binary data.
        
        Args:
            binary_data: Binary file content
            context: Optional context (architecture, compiler, etc.)
            
        Returns:
            AnalysisResult with findings
        """
        pass
    
    def validate(self) -> bool:
        """
        Validate plugin configuration.
        
        Returns:
            True if valid, False otherwise
        """
        return True
    
    def get_info(self) -> Dict[str, Any]:
        """Get plugin information."""
        return {
            "name": self.name,
            "version": self.version,
            "enabled": self.enabled,
            "description": self.__doc__ or "No description",
        }
    
    def configure(self, config: Dict[str, Any]) -> None:
        """Configure plugin with settings."""
        self.config.update(config)
    
    def _create_result(
        self,
        findings: List[Dict[str, Any]],
        metadata: Optional[Dict[str, Any]] = None,
        execution_time_ms: float = 0.0,
        confidence: float = 1.0
    ) -> AnalysisResult:
        """Helper to create analysis result."""
        return AnalysisResult(
            plugin_name=self.name,
            findings=findings,
            metadata=metadata or {},
            execution_time_ms=execution_time_ms,
            timestamp=datetime.utcnow().isoformat(),
            confidence=confidence
        )

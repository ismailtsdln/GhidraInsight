"""Plugin SDK for GhidraInsight - Extend analysis capabilities with custom modules."""

from .base import BaseAnalyzer, AnalysisResult
from .registry import PluginRegistry
from .loader import PluginLoader

__all__ = ["BaseAnalyzer", "AnalysisResult", "PluginRegistry", "PluginLoader"]

"""Plugin registry for managing custom analyzers."""

from typing import Dict, List, Optional
import logging
from .base import BaseAnalyzer

logger = logging.getLogger(__name__)


class PluginRegistry:
    """Registry for managing analysis plugins."""
    
    _instance: Optional["PluginRegistry"] = None
    _plugins: Dict[str, BaseAnalyzer] = {}
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def register(self, plugin: BaseAnalyzer) -> bool:
        """
        Register a plugin.
        
        Args:
            plugin: Plugin instance to register
            
        Returns:
            True if registered successfully, False otherwise
        """
        if not isinstance(plugin, BaseAnalyzer):
            logger.error(f"Invalid plugin type: {type(plugin)}")
            return False
        
        if not plugin.validate():
            logger.error(f"Plugin {plugin.name} failed validation")
            return False
        
        if plugin.name in self._plugins:
            logger.warning(f"Plugin {plugin.name} already registered, overwriting")
        
        self._plugins[plugin.name] = plugin
        logger.info(f"Registered plugin: {plugin.name} v{plugin.version}")
        return True
    
    def unregister(self, name: str) -> bool:
        """Unregister a plugin."""
        if name in self._plugins:
            del self._plugins[name]
            logger.info(f"Unregistered plugin: {name}")
            return True
        return False
    
    def get(self, name: str) -> Optional[BaseAnalyzer]:
        """Get a plugin by name."""
        return self._plugins.get(name)
    
    def list_all(self) -> List[BaseAnalyzer]:
        """List all registered plugins."""
        return list(self._plugins.values())
    
    def list_enabled(self) -> List[BaseAnalyzer]:
        """List only enabled plugins."""
        return [p for p in self._plugins.values() if p.enabled]
    
    def get_info(self) -> Dict[str, Dict[str, Any]]:
        """Get information about all plugins."""
        return {name: plugin.get_info() for name, plugin in self._plugins.items()}

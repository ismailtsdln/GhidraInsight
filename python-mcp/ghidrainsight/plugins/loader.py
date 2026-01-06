"""Plugin loader for dynamic plugin discovery and loading."""

import importlib
import importlib.util
import os
from pathlib import Path
from typing import List, Optional
import logging
from .base import BaseAnalyzer
from .registry import PluginRegistry

logger = logging.getLogger(__name__)


class PluginLoader:
    """Load plugins from filesystem or Python packages."""
    
    def __init__(self, plugin_dir: Optional[str] = None):
        """
        Initialize plugin loader.
        
        Args:
            plugin_dir: Directory to search for plugins (default: ./plugins)
        """
        self.plugin_dir = Path(plugin_dir) if plugin_dir else Path("./plugins")
        self.registry = PluginRegistry()
    
    def load_from_file(self, file_path: str) -> Optional[BaseAnalyzer]:
        """
        Load plugin from a Python file.
        
        Args:
            file_path: Path to plugin file
            
        Returns:
            Plugin instance or None if failed
        """
        try:
            spec = importlib.util.spec_from_file_location("plugin", file_path)
            if spec is None or spec.loader is None:
                logger.error(f"Failed to create spec for {file_path}")
                return None
            
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Look for plugin class
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (isinstance(attr, type) and 
                    issubclass(attr, BaseAnalyzer) and 
                    attr != BaseAnalyzer):
                    plugin = attr()
                    if self.registry.register(plugin):
                        return plugin
            
            logger.warning(f"No plugin class found in {file_path}")
            return None
            
        except Exception as e:
            logger.error(f"Failed to load plugin from {file_path}: {e}")
            return None
    
    def load_from_directory(self, directory: Optional[str] = None) -> List[BaseAnalyzer]:
        """
        Load all plugins from a directory.
        
        Args:
            directory: Directory to search (default: self.plugin_dir)
            
        Returns:
            List of loaded plugins
        """
        dir_path = Path(directory) if directory else self.plugin_dir
        if not dir_path.exists():
            logger.warning(f"Plugin directory does not exist: {dir_path}")
            return []
        
        plugins = []
        for file_path in dir_path.glob("*.py"):
            if file_path.name.startswith("_"):
                continue
            
            plugin = self.load_from_file(str(file_path))
            if plugin:
                plugins.append(plugin)
        
        logger.info(f"Loaded {len(plugins)} plugins from {dir_path}")
        return plugins
    
    def load_from_package(self, package_name: str) -> Optional[BaseAnalyzer]:
        """
        Load plugin from installed Python package.
        
        Args:
            package_name: Python package name
            
        Returns:
            Plugin instance or None if failed
        """
        try:
            module = importlib.import_module(package_name)
            
            # Look for plugin class
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (isinstance(attr, type) and 
                    issubclass(attr, BaseAnalyzer) and 
                    attr != BaseAnalyzer):
                    plugin = attr()
                    if self.registry.register(plugin):
                        return plugin
            
            logger.warning(f"No plugin class found in package {package_name}")
            return None
            
        except Exception as e:
            logger.error(f"Failed to load plugin from package {package_name}: {e}")
            return None

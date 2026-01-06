# Plugin Development Guide

GhidraInsight provides a plugin SDK for creating custom analysis modules. This guide shows you how to develop, test, and distribute your plugins.

## Overview

Plugins extend GhidraInsight's analysis capabilities with custom logic. They can:
- Detect custom patterns
- Perform specialized analysis
- Integrate with external tools
- Add domain-specific checks

## Quick Start

### 1. Create a Plugin

```python
from ghidrainsight.plugins import BaseAnalyzer, AnalysisResult
from typing import Dict, Any, Optional, List

class MyCustomAnalyzer(BaseAnalyzer):
    def __init__(self):
        super().__init__(
            name="my_custom_analyzer",
            version="1.0.0"
        )
    
    def analyze(self, binary_data: bytes, context: Optional[Dict[str, Any]] = None) -> AnalysisResult:
        findings = []
        
        # Your analysis logic here
        # ...
        
        return self._create_result(
            findings=findings,
            metadata={"custom": "data"},
            execution_time_ms=100.0,
            confidence=0.9
        )
```

### 2. Register Your Plugin

```python
from ghidrainsight.plugins import PluginRegistry

registry = PluginRegistry()
plugin = MyCustomAnalyzer()
registry.register(plugin)
```

### 3. Use Your Plugin

```python
# Load plugin
from ghidrainsight.plugins import PluginLoader

loader = PluginLoader(plugin_dir="./my_plugins")
loader.load_from_file("my_custom_analyzer.py")

# Use in analysis
result = plugin.analyze(binary_data)
print(result.findings)
```

## Plugin Structure

### BaseAnalyzer Class

All plugins must inherit from `BaseAnalyzer`:

```python
class BaseAnalyzer(ABC):
    def __init__(self, name: str, version: str = "1.0.0")
    def analyze(self, binary_data: bytes, context: Optional[Dict[str, Any]] = None) -> AnalysisResult
    def validate(self) -> bool
    def get_info(self) -> Dict[str, Any]
    def configure(self, config: Dict[str, Any]) -> None
```

### AnalysisResult

Return analysis results using `AnalysisResult`:

```python
@dataclass
class AnalysisResult:
    plugin_name: str
    findings: List[Dict[str, Any]]
    metadata: Dict[str, Any]
    execution_time_ms: float
    timestamp: str
    confidence: float = 1.0
```

## Examples

See `examples/plugins/example_custom_analyzer.py` for a complete example.

## Plugin Registry

The `PluginRegistry` manages all registered plugins:

```python
from ghidrainsight.plugins import PluginRegistry

registry = PluginRegistry()

# Register
registry.register(plugin)

# List all
plugins = registry.list_all()

# List enabled
enabled = registry.list_enabled()

# Get info
info = registry.get_info()
```

## Plugin Loader

Load plugins dynamically:

```python
from ghidrainsight.plugins import PluginLoader

# Load from file
loader = PluginLoader()
plugin = loader.load_from_file("my_plugin.py")

# Load from directory
plugins = loader.load_from_directory("./plugins")

# Load from package
plugin = loader.load_from_package("my_plugin_package")
```

## Best Practices

1. **Naming**: Use descriptive, unique plugin names
2. **Versioning**: Follow semantic versioning
3. **Error Handling**: Handle exceptions gracefully
4. **Performance**: Optimize for large binaries
5. **Documentation**: Document your plugin's purpose and findings

## Distribution

### As Python Package

```python
# setup.py
from setuptools import setup

setup(
    name="ghidrainsight-my-plugin",
    version="1.0.0",
    py_modules=["my_plugin"],
    install_requires=["ghidrainsight"],
)
```

### As File

Place your plugin in the `plugins/` directory and it will be auto-loaded.

## Testing

```python
import pytest
from ghidrainsight.plugins import MyCustomAnalyzer

def test_my_plugin():
    plugin = MyCustomAnalyzer()
    result = plugin.analyze(b"test binary data")
    assert len(result.findings) > 0
```

## Community Plugins

Share your plugins with the community:
1. Create a GitHub repository
2. Add `ghidrainsight-plugin` topic
3. Submit to plugin marketplace (coming soon)

---

For more examples, see `examples/plugins/`.

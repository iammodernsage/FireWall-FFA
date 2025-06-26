#!/usr/bin/env python3
import abc
import inspect
import json
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from enum import Enum, auto
import logging
import time
import functools
from pathlib import Path
import yaml

# Configure module-level logger
logger = logging.getLogger(__name__)

class PluginType(Enum):
    """Supported plugin types"""
    PRE_PROCESSOR = auto()    # Runs before WAF rules
    POST_PROCESSOR = auto()   # Runs after WAF rules
    ANALYZER = auto()         # Background analysis
    LOGGER = auto()           # Log processing
    CUSTOM_RULE = auto()      # Adds new rule types

@dataclass
class RequestContext:
    """Immutable request data structure"""
    method: str
    uri: str
    headers: Dict[str, str]
    body: bytes
    remote_ip: str
    timestamp: float = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class ResponseContext:

    """Mutable response data structure"""

    status: int = 200
    headers: Dict[str, str] = None
    body: bytes = b""
    action: str = "allow"  # allow, block, challenge, log

    def set_block(self, reason: str, status: int = 403) -> None:
        self.status = status
        self.action = "block"
        self.body = json.dumps({"error": reason}).encode()

class PluginPhase(Enum):

    """Execution phases for PRE/POST processors"""

    REQUEST_HEADERS = auto()
    REQUEST_BODY = auto()
    RESPONSE_HEADERS = auto()
    RESPONSE_BODY = auto()

class PluginMetadata:

    def __init__(self, 
                 name: str,
                 plugin_type: PluginType,
                 version: str = "1.0",
                 description: str = "",
                 author: str = "",
                 config_schema: Dict = None,
                 requirements: List[str] = None):
        self.name = name
        self.type = plugin_type
        self.version = version
        self.description = description
        self.author = author
        self.config_schema = config_schema or {}
        self.requirements = requirements or []

    def validate_config(self, config: Dict) -> bool:

        """Validate config against schema (simplified example)"""

        try:
            if self.config_schema.get("type") == "object":
                for field, spec in self.config_schema.get("properties", {}).items():
                    if spec.get("required", False) and field not in config:
                        raise ValueError(f"Missing required field: {field}")
            return True
        except Exception as e:
            logger.error(f"Config validation failed: {str(e)}")
            return False

class WAFPlugin(abc.ABC):

    """Base class for all WAF plugins"""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self._validate_config()

    @property
    @abc.abstractmethod
    def metadata(self) -> PluginMetadata:
        """Must return plugin metadata"""
        pass

    def _validate_config(self) -> None:
        """Validate plugin configuration"""
        if not self.metadata.validate_config(self.config):
            raise ValueError("Invalid plugin configuration")

    def initialize(self) -> None:
        """Called when plugin is loaded"""
        pass

    def shutdown(self) -> None:
        """Called when plugin is unloaded"""
        pass

class PreProcessorPlugin(WAFPlugin):

    """Pre-process requests before WAF rules evaluation"""

    @abc.abstractmethod
    def process(self, 
               request: RequestContext, 
               response: ResponseContext,
               phase: PluginPhase) -> Optional[ResponseContext]:
        """
        Process the request/response
        Return None to continue processing, or ResponseContext to short-circuit
        """
        pass

class PostProcessorPlugin(WAFPlugin):

    """Post-process requests after WAF rules evaluation"""

    @abc.abstractmethod
    def process(self,
               request: RequestContext,
               response: ResponseContext) -> None:
        """Modify the final response if needed"""
        pass

class AnalyzerPlugin(WAFPlugin):

    """Background analysis plugins"""

    @abc.abstractmethod
    def analyze(self, request: RequestContext) -> None:
        """Asynchronously analyze requests"""
        pass

class LoggingPlugin(WAFPlugin):
    """Log processing plugins"""
    @abc.abstractmethod
    def log(self, 
           request: RequestContext, 
           response: ResponseContext) -> None:
        """Handle request/response logging"""
        pass

class RulePlugin(WAFPlugin):

    """Custom rule implementation plugins"""

    @abc.abstractmethod
    def evaluate(self, request: RequestContext) -> Dict[str, Any]:
        """
        Evaluate the request against custom rules
        Return: {
            "match": bool,
            "metadata": dict,
            "action": "allow|block|challenge|log"
        }
        """
        pass

# Decorators for plugin developers

def plugin_metadata(meta: PluginMetadata) -> Callable:

    """Class decorator to set plugin metadata"""

    def decorator(cls):
        cls.metadata = meta
        return cls
    return decorator

def timed_execution(func: Callable) -> Callable:

    """Decorator to log execution time"""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        logger.debug(f"{func.__name__} executed in {time.time() - start:.4f}s")
        return result
    return wrapper

# Plugin manager and utilities

class PluginManager:

  """Loads and manages plugin lifecycle"""

    def __init__(self, plugin_dir: str = "/etc/betterfirewall/plugins"):
        self.plugins: Dict[PluginType, List[WAFPlugin]] = {
            pt: [] for pt in PluginType
        }
        self.plugin_dir = Path(plugin_dir)
        self._loaded_plugins = {}

    def load_all(self) -> None:
        """Load all plugins from configured directory"""

        for plugin_file in self.plugin_dir.glob("*.py"):
            try:
                self.load_plugin(plugin_file)
            except Exception as e:
                logger.error(f"Failed to load {plugin_file}: {str(e)}")

    def load_plugin(self, plugin_path: Path) -> WAFPlugin:

        # Simplified plugin loading - in production use importlib
        module_name = plugin_path.stem
        spec = inspect.getmodulename(str(plugin_path))
        module = inspect.getmodule(inspect.currentframe())

        # Check for plugin class (convention: class name matches file name)
        plugin_class = getattr(module, module_name, None)
        if not plugin_class or not issubclass(plugin_class, WAFPlugin):
            raise ValueError(f"No valid plugin class found in {plugin_path}")

        # Load config if exists
        config_path = plugin_path.with_suffix('.yaml')
        config = {}
        if config_path.exists():
            with open(config_path) as f:
                config = yaml.safe_load(f) or {}

        # Instantiate plugin
        plugin = plugin_class(config)
        self._register_plugin(plugin)
        return plugin

    def _register_plugin(self, plugin: WAFPlugin) -> None:
        """Register plugin by type"""
        if isinstance(plugin, PreProcessorPlugin):
            self.plugins[PluginType.PRE_PROCESSOR].append(plugin)
        elif isinstance(plugin, PostProcessorPlugin):
            self.plugins[PluginType.POST_PROCESSOR].append(plugin)
        elif isinstance(plugin, AnalyzerPlugin):
            self.plugins[PluginType.ANALYZER].append(plugin)
        elif isinstance(plugin, LoggingPlugin):
            self.plugins[PluginType.LOGGER].append(plugin)
        elif isinstance(plugin, RulePlugin):
            self.plugins[PluginType.CUSTOM_RULE].append(plugin)
        else:
            raise ValueError(f"Unknown plugin type: {type(plugin)}")

        self._loaded_plugins[plugin.metadata.name] = plugin
        logger.info(f"Loaded plugin: {plugin.metadata.name} v{plugin.metadata.version}")

    def get_plugin(self, name: str) -> Optional[WAFPlugin]:
        """Get plugin by name"""
        return self._loaded_plugins.get(name)

    def shutdown_all(self) -> None:
        """Gracefully shutdown all plugins"""
        for plugin in self._loaded_plugins.values():
            try:
                plugin.shutdown()
            except Exception as e:
                logger.error(f"Error shutting down {plugin.metadata.name}: {str(e)}")

# Example plugin implementation
@plugin_metadata(PluginMetadata(
    name="GeoBlock",
    plugin_type=PluginType.PRE_PROCESSOR,
    version="1.0",
    description="Blocks requests from specific countries",
    author="Security Team",
    config_schema={
        "type": "object",
        "properties": {
            "blocked_countries": {
                "type": "array",
                "items": {"type": "string", "pattern": "^[A-Z]{2}$"},
                "default": []
            }
        },
        "required": ["blocked_countries"]
    }
))
class GeoBlockPlugin(PreProcessorPlugin):
    """Example plugin that blocks by country code"""

    @timed_execution
    def process(self, request, response, phase):
        if phase != PluginPhase.REQUEST_HEADERS:
            return None

        country = request.headers.get("X-Country-Code")
        if country in self.config["blocked_countries"]:
            response.set_block(f"Access from {country} is restricted")
            return response
        return None

    def initialize(self):
        logger.info(f"Initialized GeoBlock with {len(self.config['blocked_countries']} countries")

# Example usage
if __name__ == "__main__":
    # Initialize plugin manager
    manager = PluginManager(plugin_dir="plugins")

    try:
        # Load plugins
        manager.load_all()

        # Simulate request
        request = RequestContext(
            method="GET",
            uri="/test",
            headers={"X-Country-Code": "RU"},
            body=b"",
            remote_ip="192.168.1.1"
        )
        response = ResponseContext()

        # Process through PRE_PROCESSOR plugins
        for plugin in manager.plugins[PluginType.PRE_PROCESSOR]:
            result = plugin.process(request, response, PluginPhase.REQUEST_HEADERS)
            if result:  # Short-circuit if response is returned
                break

        print(f"Response status: {response.status}")

    finally:
        manager.shutdown_all()

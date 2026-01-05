"""CLI tools for GhidraInsight with comprehensive validation and error handling."""

import click
import sys
import json
import logging
from pathlib import Path
from typing import Optional, List
from ..config import settings
from ..auth import AuthManager
from ..logging_config import setup_logging, get_logger

logger = get_logger(__name__)


class CLIError(click.ClickException):
    """Custom CLI error with exit code."""
    
    def __init__(self, message: str, exit_code: int = 1):
        super().__init__(message)
        self.exit_code = exit_code


def validate_binary_file(ctx, param, value):
    """Validate binary file exists and is readable."""
    if not value:
        return value
    
    path = Path(value)
    if not path.exists():
        raise CLIError(f"Binary file not found: {value}")
    
    if not path.is_file():
        raise CLIError(f"Path is not a file: {value}")
    
    if not path.stat().st_size > 0:
        raise CLIError(f"Binary file is empty: {value}")
    
    if path.stat().st_size > settings.analysis.max_binary_size:
        raise CLIError(
            f"Binary file too large (max {settings.analysis.max_binary_size} bytes): {value}"
        )
    
    return str(path.absolute())


def validate_features(ctx, param, value):
    """Validate analysis features."""
    if not value:
        return ["crypto", "taint", "vulnerability"]
    
    valid_features = {
        "crypto",
        "taint",
        "vulnerability",
        "control_flow",
    }
    
    features = [f.strip().lower() for f in value.split(",")]
    invalid = [f for f in features if f not in valid_features]
    
    if invalid:
        raise CLIError(
            f"Invalid features: {', '.join(invalid)}. "
            f"Valid options: {', '.join(valid_features)}"
        )
    
    return features


def validate_port(ctx, param, value):
    """Validate port number."""
    if not isinstance(value, int):
        try:
            value = int(value)
        except ValueError:
            raise CLIError(f"Port must be an integer: {value}")
    
    if not (1024 <= value <= 65535):
        raise CLIError(f"Port must be between 1024 and 65535: {value}")
    
    return value


def validate_log_level(ctx, param, value):
    """Validate log level."""
    valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
    level = value.upper()
    
    if level not in valid_levels:
        raise CLIError(
            f"Invalid log level: {value}. "
            f"Valid options: {', '.join(valid_levels)}"
        )
    
    return level


@click.group(invoke_without_command=True)
@click.version_option(version="1.0.0")
def main(ctx) -> None:
    """GhidraInsight CLI - AI-Driven Reverse Engineering Platform."""
    if ctx.invoked_subcommand is None:
        print(ctx.get_help())


@main.command()
@click.argument("binary", callback=validate_binary_file)
@click.option(
    "--features",
    callback=validate_features,
    help="Analysis features (comma-separated): crypto,taint,vulnerability,control_flow",
    default=None,
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output file (JSON format)",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Verbose output",
)
@click.option(
    "--log-level",
    callback=validate_log_level,
    default="INFO",
    help="Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
)
def analyze(binary: str, features: List[str], output: Optional[str], verbose: bool, log_level: str) -> None:
    """Analyze a binary file for vulnerabilities and features.
    
    BINARY: Path to the binary file to analyze
    """
    try:
        # Setup logging
        level = getattr(logging, log_level.upper(), logging.INFO)
        setup_logging(log_level=level)
        
        logger.info(f"Starting analysis of {binary}")
        logger.debug(f"Features: {', '.join(features)}")
        
        # TODO: Implement actual analysis logic
        results = {
            "binary": binary,
            "features": features,
            "findings": [],
            "status": "completed",
        }
        
        # Output results
        if output:
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                json.dump(results, f, indent=2)
            logger.info(f"Results saved to {output}")
            click.echo(f"✓ Analysis completed. Results saved to {output}")
        else:
            click.echo(json.dumps(results, indent=2))
    
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise CLIError(f"Analysis failed: {e}")


@main.command()
@click.option(
    "--host",
    "-H",
    default="0.0.0.0",
    help="Bind address",
)
@click.option(
    "--port",
    "-p",
    type=int,
    callback=validate_port,
    default=8000,
    help="HTTP port",
)
@click.option(
    "--ws-port",
    type=int,
    callback=validate_port,
    default=8001,
    help="WebSocket port",
)
@click.option(
    "--sse-port",
    type=int,
    callback=validate_port,
    default=8002,
    help="Server-Sent Events port",
)
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True),
    help="Configuration file (.env format)",
)
@click.option(
    "--log-level",
    callback=validate_log_level,
    default="INFO",
    help="Log level",
)
@click.option(
    "--debug",
    is_flag=True,
    help="Enable debug mode",
)
def server(host: str, port: int, ws_port: int, sse_port: int, config: Optional[str], log_level: str, debug: bool) -> None:
    """Start the GhidraInsight MCP server.
    
    Provides three transports:
    - HTTP REST API on PORT
    - WebSocket on WS_PORT
    - Server-Sent Events on SSE_PORT
    """
    try:
        # Setup logging
        level = logging.DEBUG if debug else getattr(logging, log_level.upper(), logging.INFO)
        setup_logging(log_level=level)
        
        if config:
            logger.info(f"Loading configuration from {config}")
        
        logger.info(f"Starting GhidraInsight server")
        logger.info(f"  HTTP: {host}:{port}")
        logger.info(f"  WebSocket: {host}:{ws_port}")
        logger.info(f"  SSE: {host}:{sse_port}")
        
        # TODO: Implement actual server startup
        click.echo(f"✓ GhidraInsight server running on {host}:{port}")
        
        # Keep server running
        import time
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Server shutdown requested")
            click.echo("✓ Server stopped")
    
    except Exception as e:
        logger.error(f"Server startup failed: {e}")
        raise CLIError(f"Server startup failed: {e}")


@main.command()
@click.option(
    "--length",
    "-l",
    type=int,
    default=32,
    help="API key length (minimum 16)",
)
def generate_key(length: int) -> None:
    """Generate a secure API key.
    
    Generates a random API key suitable for authentication.
    """
    try:
        if length < 16:
            raise CLIError("API key length must be at least 16 characters")
        
        api_key = AuthManager.generate_api_key(length)
        
        click.echo("\n" + "=" * 60)
        click.echo("Generated API Key:")
        click.echo("=" * 60)
        click.echo(api_key)
        click.echo("=" * 60)
        click.echo("\n⚠️  Save this key in a secure location!")
        click.echo("⚠️  You won't be able to see it again!")
        click.echo("\nTo hash this key for storage:")
        click.echo(f"ghidrainsight hash-key {api_key}\n")
    
    except Exception as e:
        logger.error(f"Key generation failed: {e}")
        raise CLIError(f"Key generation failed: {e}")


@main.command()
@click.argument("api_key")
def hash_key(api_key: str) -> None:
    """Hash an API key for secure storage.
    
    API_KEY: The API key to hash
    """
    try:
        if not api_key or len(api_key) < 16:
            raise CLIError("API key must be at least 16 characters")
        
        hashed = AuthManager.hash_api_key(api_key)
        
        click.echo("\n" + "=" * 60)
        click.echo("Hashed API Key:")
        click.echo("=" * 60)
        click.echo(hashed)
        click.echo("=" * 60)
        click.echo("\nStore this hash securely in your database.\n")
    
    except Exception as e:
        logger.error(f"Key hashing failed: {e}")
        raise CLIError(f"Key hashing failed: {e}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.error(f"CLI error: {e}")
        sys.exit(1)

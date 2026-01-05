"""Application configuration module with validation and environment support."""

from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings
from typing import Optional, List, Dict, Any
import logging
import os
from pathlib import Path


class DatabaseConfig(BaseModel):
    """Database configuration."""

    enabled: bool = True
    url: Optional[str] = Field(default_factory=lambda: os.getenv("DATABASE_URL"))
    pool_size: int = 10
    max_overflow: int = 20
    echo: bool = False


class LoggingConfig(BaseModel):
    """Logging configuration."""

    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file: Optional[str] = None
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    backup_count: int = 5


class SecurityConfig(BaseModel):
    """Security configuration."""

    jwt_secret: str = Field(min_length=32)
    jwt_algorithm: str = "HS256"
    jwt_expiry: int = 3600  # 1 hour
    api_key_enabled: bool = True
    rate_limit: int = 60  # requests per minute
    cors_origins: List[str] = ["http://localhost:3000", "http://localhost:5173"]
    allowed_hosts: List[str] = ["localhost", "127.0.0.1"]
    tls_enabled: bool = False
    tls_cert_path: Optional[str] = None
    tls_key_path: Optional[str] = None

    @field_validator("jwt_algorithm")
    @classmethod
    def validate_jwt_algorithm(cls, v: str) -> str:
        """Validate JWT algorithm is supported."""
        allowed = {"HS256", "HS384", "HS512", "RS256", "RS384", "RS512"}
        if v not in allowed:
            raise ValueError(f"JWT algorithm must be one of {allowed}, got {v}")
        return v

    @field_validator("rate_limit")
    @classmethod
    def validate_rate_limit(cls, v: int) -> int:
        """Validate rate limit is positive."""
        if v < 1:
            raise ValueError("rate_limit must be at least 1")
        return v


class AnalysisConfig(BaseModel):
    """Analysis configuration."""

    timeout: int = 300  # 5 minutes
    max_binary_size: int = 500 * 1024 * 1024  # 500MB
    enable_crypto_detection: bool = True
    enable_taint_analysis: bool = True
    enable_vulnerability_detection: bool = True
    enable_control_flow_analysis: bool = True


class CacheConfig(BaseModel):
    """Cache configuration."""

    enabled: bool = True
    ttl: int = 3600  # 1 hour
    max_size: int = 1000  # max cached items
    backend: str = "memory"  # memory, redis, or file


class Settings(BaseSettings):
    """
    Application settings with environment variable support.

    Load from environment variables with prefix GHIDRA_
    or from .env file.
    """

    # Application
    app_name: str = "GhidraInsight"
    app_version: str = "1.0.0"
    debug: bool = False

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    ws_port: int = 8001
    sse_port: int = 8002

    # Database
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)

    # Security
    security: SecurityConfig = Field(
        default_factory=lambda: SecurityConfig(
            jwt_secret=os.getenv("GHIDRA_JWT_SECRET", "change-me-in-production-32-chars-min!!")
        )
    )

    # Logging
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    # Analysis
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)

    # Cache
    cache: CacheConfig = Field(default_factory=CacheConfig)

    # Optional features
    enable_ui: bool = True
    enable_metrics: bool = True

    class Config:
        env_file = ".env"
        env_nested_delimiter = "__"
        case_sensitive = False

    @field_validator("port", "ws_port", "sse_port")
    @classmethod
    def validate_ports(cls, v: int) -> int:
        """Validate port numbers are in valid range."""
        if not (1024 <= v <= 65535):
            raise ValueError(f"Port must be between 1024 and 65535, got {v}")
        return v

    def validate_paths(self) -> None:
        """Validate TLS certificate paths if enabled."""
        if self.security.tls_enabled:
            if not self.security.tls_cert_path:
                raise ValueError("tls_cert_path required when tls_enabled=true")
            if not self.security.tls_key_path:
                raise ValueError("tls_key_path required when tls_enabled=true")

            cert_path = Path(self.security.tls_cert_path)
            key_path = Path(self.security.tls_key_path)

            if not cert_path.exists():
                raise ValueError(f"TLS certificate not found: {self.security.tls_cert_path}")
            if not key_path.exists():
                raise ValueError(f"TLS key not found: {self.security.tls_key_path}")

    def get_log_level(self) -> int:
        """Get numeric log level."""
        level_map = {
            "DEBUG": logging.DEBUG,
            "INFO": logging.INFO,
            "WARNING": logging.WARNING,
            "ERROR": logging.ERROR,
            "CRITICAL": logging.CRITICAL,
        }
        return level_map.get(self.logging.level.upper(), logging.INFO)

    def to_dict(self) -> Dict[str, Any]:
        """Convert settings to dictionary (safe for logging)."""
        data = self.model_dump()
        # Remove sensitive data
        if "security" in data and "jwt_secret" in data["security"]:
            data["security"]["jwt_secret"] = "***"
        return data


# Load settings
try:
    settings = Settings()
    settings.validate_paths()
except Exception as e:
    # Provide helpful error message
    import sys
    print(f"Configuration Error: {e}", file=sys.stderr)
    sys.exit(1)

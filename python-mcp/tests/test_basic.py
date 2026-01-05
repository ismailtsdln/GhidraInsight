"""Tests for GhidraInsight MCP Server."""

import pytest
from ghidrainsight.config import Settings
from ghidrainsight.auth import AuthManager


class TestConfig:
    """Test configuration management."""

    def test_settings_creation(self):
        """Test that settings can be created."""
        settings = Settings(jwt_secret="test_secret_key_that_is_long_enough_for_testing")
        assert settings.logging.level == "INFO"
        assert settings.host == "0.0.0.0"
        assert settings.port == 8000


class TestAuth:
    """Test authentication functionality."""

    def test_auth_manager_creation(self):
        """Test AuthManager creation."""
        auth = AuthManager(secret="test_secret_key_that_is_long_enough_for_testing")
        assert auth is not None

    def test_auth_manager_invalid_secret(self):
        """Test AuthManager with invalid secret."""
        with pytest.raises(ValueError):
            AuthManager(secret="short")


class TestCore:
    """Test core functionality."""

    def test_import(self):
        """Test that modules can be imported."""
        from ghidrainsight.core.client import AnalysisResult
        assert AnalysisResult is not None

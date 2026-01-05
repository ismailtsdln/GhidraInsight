"""Test configuration."""

import pytest
from typing import AsyncGenerator

@pytest.fixture
async def client() -> AsyncGenerator:
    """Provide test client."""
    pass

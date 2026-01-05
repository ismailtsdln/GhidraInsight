"""Authentication module with comprehensive security features."""

from typing import Optional, Dict, Any
import jwt
from datetime import datetime, timedelta
import hashlib
import secrets
import logging

logger = logging.getLogger(__name__)


class AuthenticationError(Exception):
    """Custom authentication exception."""
    pass


class TokenExpiredError(AuthenticationError):
    """Token has expired."""
    pass


class InvalidTokenError(AuthenticationError):
    """Token is invalid."""
    pass


class AuthManager:
    """Handles authentication, authorization, and token management."""
    
    def __init__(
        self,
        secret: str,
        algorithm: str = "HS256",
        token_expiry: int = 3600,
    ):
        """
        Initialize auth manager.
        
        Args:
            secret: JWT secret key (should be at least 32 characters)
            algorithm: JWT algorithm (HS256, RS256, etc.)
            token_expiry: Default token expiration time in seconds
            
        Raises:
            ValueError: If secret is too short or invalid
        """
        if not secret or len(secret) < 32:
            raise ValueError("Secret must be at least 32 characters long")
        
        if algorithm not in ["HS256", "HS384", "HS512", "RS256"]:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        self.secret = secret
        self.algorithm = algorithm
        self.token_expiry = token_expiry
        logger.info(f"AuthManager initialized with algorithm: {algorithm}")
    
    def generate_token(
        self,
        subject: str,
        expires_in: Optional[int] = None,
        additional_claims: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Generate JWT token with standard and custom claims.
        
        Args:
            subject: Token subject (user ID, API key ID, etc.)
            expires_in: Token expiration time in seconds (uses default if None)
            additional_claims: Additional claims to include in token
            
        Returns:
            JWT token string
            
        Raises:
            ValueError: If subject is empty
        """
        if not subject or not isinstance(subject, str):
            raise ValueError("Subject must be a non-empty string")
        
        expires_in = expires_in or self.token_expiry
        now = datetime.utcnow()
        
        payload = {
            "sub": subject,
            "exp": now + timedelta(seconds=expires_in),
            "iat": now,
            "nbf": now,  # Not before
            "jti": secrets.token_urlsafe(16),  # JWT ID for revocation tracking
        }
        
        if additional_claims and isinstance(additional_claims, dict):
            payload.update(additional_claims)
        
        try:
            token = jwt.encode(payload, self.secret, algorithm=self.algorithm)
            logger.debug(f"Token generated for subject: {subject}")
            return token
        except Exception as e:
            logger.error(f"Failed to generate token: {e}")
            raise AuthenticationError("Token generation failed")
    
    def verify_token(self, token: str) -> Dict[str, Any]:
        """
        Verify JWT token and return decoded payload.
        
        Args:
            token: JWT token string
            
        Returns:
            Decoded token payload
            
        Raises:
            InvalidTokenError: If token is invalid
            TokenExpiredError: If token has expired
        """
        try:
            payload = jwt.decode(
                token,
                self.secret,
                algorithms=[self.algorithm],
                options={"verify_signature": True, "verify_exp": True},
            )
            logger.debug(f"Token verified for subject: {payload.get('sub')}")
            return payload
        except jwt.ExpiredSignatureError as e:
            logger.warning(f"Token expired: {e}")
            raise TokenExpiredError("Token has expired")
        except jwt.InvalidSignatureError as e:
            logger.warning(f"Invalid token signature: {e}")
            raise InvalidTokenError("Token signature is invalid")
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            raise InvalidTokenError(f"Token is invalid: {str(e)}")
    
    @staticmethod
    def hash_api_key(api_key: str) -> str:
        """
        Hash an API key using SHA-256.
        
        Args:
            api_key: Raw API key
            
        Returns:
            Hashed key in hex format
            
        Raises:
            ValueError: If API key is empty
        """
        if not api_key or not isinstance(api_key, str):
            raise ValueError("API key must be a non-empty string")
        
        return hashlib.sha256(api_key.encode()).hexdigest()
    
    @staticmethod
    def verify_api_key(api_key: str, hashed_key: str) -> bool:
        """
        Verify an API key against its hash.
        
        Args:
            api_key: Raw API key
            hashed_key: Previously hashed key
            
        Returns:
            True if API key matches hash, False otherwise
        """
        if not api_key or not hashed_key:
            return False
        
        try:
            return AuthManager.hash_api_key(api_key) == hashed_key
        except Exception as e:
            logger.error(f"API key verification failed: {e}")
            return False
    
    @staticmethod
    def generate_api_key(length: int = 32) -> str:
        """
        Generate a secure random API key.
        
        Args:
            length: Length of the API key in characters
            
        Returns:
            Secure random API key
            
        Raises:
            ValueError: If length is too short
        """
        if length < 16:
            raise ValueError("API key length must be at least 16 characters")
        
        return secrets.token_urlsafe(length)

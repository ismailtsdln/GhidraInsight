"""Security utilities for GhidraInsight."""

import hashlib
import secrets
import re
from typing import Optional, List, Dict, Any
import logging

logger = logging.getLogger(__name__)


class SecurityValidator:
    """Security validation utilities."""
    
    # Suspicious patterns that might indicate malicious code
    SUSPICIOUS_PATTERNS = [
        rb'eval\s*\(',
        rb'system\s*\(',
        rb'exec\s*\(',
        rb'__import__',
        rb'subprocess',
        rb'os\.system',
        rb'shell_exec',
        rb'passthru',
        rb'base64_decode',
        rb'gzuncompress',
        rb'str_rot13',
        rb'chr\s*\(',
        rb'ord\s*\(',
    ]
    
    # File signatures that require special handling (not blocked)
    BINARY_SIGNATURES = {
        b'MZ': 'PE',  # PE executable (Windows)
        b'\x7fELF': 'ELF',  # ELF executable (Linux)
        b'\xca\xfe\xba\xbe': 'Java',  # Java class
        b'\xfe\xed\xfa\xce': 'Mach-O',  # Mach-O binary (macOS 64-bit)
        b'\xfe\xed\xfa\xcf': 'Mach-O',  # Mach-O binary (macOS 32-bit)
    }
    
    @classmethod
    def validate_binary_size(cls, data: bytes, max_size: int = 1024 * 1024 * 1024) -> bool:
        """
        Validate binary file size - increased for malware analysis.
        
        Args:
            data: Binary data
            max_size: Maximum allowed size in bytes (default: 1GB for malware analysis)
            
        Returns:
            True if size is valid
        """
        return len(data) <= max_size
    
    @classmethod
    def contains_malware_indicators(cls, data: bytes) -> List[str]:
        """
        Check for malware analysis indicators (not suspicious patterns).
        
        These are indicators that malware analysts look for, not things to block.
        
        Args:
            data: Binary data to check
            
        Returns:
            List of detected malware indicators for analysis context
        """
        malware_indicators = [
            b'eval(',  # Code execution (common in malware)
            b'system(',  # System calls (common in malware)
            b'exec(',  # Python exec (common in malware)
            b'__import__',  # Dynamic imports (obfuscation)
            b'subprocess',  # Subprocess calls (malware behavior)
            b'os.system',  # OS system calls (malware behavior)
        ]
        
        detected = []
        for pattern in malware_indicators:
            if pattern in data:
                detected.append(pattern.decode('utf-8', errors='ignore'))
        return detected
    
    @classmethod
    def contains_suspicious_patterns(cls, data: bytes) -> List[str]:
        """
        Check for suspicious patterns in binary data.
        
        Args:
            data: Binary data to check
            
        Returns:
            List of detected suspicious patterns
        """
        detected = []
        for pattern in cls.SUSPICIOUS_PATTERNS:
            if pattern in data:
                detected.append(pattern.decode('utf-8', errors='ignore'))
        return detected
    
    @classmethod
    def detect_file_type(cls, data: bytes) -> Optional[str]:
        """
        Detect binary file type from signature.
        
        Args:
            data: Binary data to check
            
        Returns:
            File type string or None if unknown
        """
        for signature, file_type in cls.BINARY_SIGNATURES.items():
            if data.startswith(signature):
                return file_type
        return None
    
    @classmethod
    def sanitize_string(cls, text: str, max_length: int = 200) -> str:
        """
        Sanitize string output.
        
        Args:
            text: Text to sanitize
            max_length: Maximum allowed length
            
        Returns:
            Sanitized text
        """
        if not text:
            return ""
        
        # Remove null bytes and control characters
        sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', text)
        
        # Truncate if too long
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length] + "..."
        
        return sanitized
    
    @classmethod
    def sanitize_results_for_display(cls, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize analysis results for UI display (not for analysis).
        
        Only limits data for display purposes, doesn't remove analysis-critical data.
        
        Args:
            results: Raw analysis results
            
        Returns:
            Display-safe results (preserves all analysis data)
        """
        sanitized = results.copy()
        
        if 'results' in sanitized:
            for feature, result in sanitized['results'].items():
                if isinstance(result, dict):
                    # Only limit strings for display, don't filter content
                    if 'strings' in result:
                        # Keep all strings but limit length for display
                        strings = result['strings']
                        if isinstance(strings, list):
                            # Limit to 1000 strings for display (not 100)
                            result['strings'] = strings[:1000]
                            # Truncate very long strings for display only
                            result['strings'] = [
                                s[:500] + "..." if len(s) > 500 else s 
                                for s in result['strings']
                            ]
                    
                    # Don't filter any content - malware analysts need all data
                    # Only limit display length for very long text fields
                    for key, value in result.items():
                        if isinstance(value, str) and len(value) > 1000:
                            result[key] = value[:1000] + "..."  # Truncate for display
                        elif isinstance(value, list) and value and isinstance(value[0], str):
                            result[key] = value[:1000]  # Limit list size for display
        
        return sanitized


class InputValidator:
    """Input validation utilities."""
    
    @staticmethod
    def validate_hex_address(address: str) -> bool:
        """
        Validate hexadecimal address format.
        
        Args:
            address: Address string to validate
            
        Returns:
            True if valid hex address
        """
        if not address or not isinstance(address, str):
            return False
        
        # Remove 0x prefix if present
        if address.startswith('0x'):
            address = address[2:]
        
        # Check if it's a valid hex string
        try:
            int(address, 16)
            return len(address) <= 16  # Max 64-bit address
        except ValueError:
            return False
    
    @staticmethod
    def validate_feature_list(features: List[str]) -> bool:
        """
        Validate feature list.
        
        Args:
            features: List of feature names
            
        Returns:
            True if valid
        """
        if not isinstance(features, list):
            return False
        
        valid_features = {
            'basic_info', 'strings', 'entropy', 'crypto', 'taint',
            'vulnerability', 'control_flow_anomalies', 'ml_vulnerability_detection',
            'exploit_patterns', 'semantic_analysis'
        }
        
        return all(feature in valid_features for feature in features)
    
    @staticmethod
    def validate_file_path(path: str) -> bool:
        """
        Validate file path for security.
        
        Args:
            path: File path to validate
            
        Returns:
            True if safe
        """
        if not path or not isinstance(path, str):
            return False
        
        # Block path traversal attempts
        dangerous_patterns = ['../', '..\\', '~/', '/etc/', '/var/', '/sys/']
        return not any(pattern in path for pattern in dangerous_patterns)


class RateLimiter:
    """Simple rate limiter for API endpoints."""
    
    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        """
        Initialize rate limiter.
        
        Args:
            max_requests: Maximum requests per window
            window_seconds: Time window in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = {}  # {client_ip: [timestamp1, timestamp2, ...]}
    
    def is_allowed(self, client_ip: str) -> bool:
        """
        Check if request is allowed.
        
        Args:
            client_ip: Client IP address
            
        Returns:
            True if request is allowed
        """
        import time
        
        now = time.time()
        
        # Clean old requests
        if client_ip in self.requests:
            self.requests[client_ip] = [
                ts for ts in self.requests[client_ip]
                if now - ts < self.window_seconds
            ]
        else:
            self.requests[client_ip] = []
        
        # Check if under limit
        if len(self.requests[client_ip]) < self.max_requests:
            self.requests[client_ip].append(now)
            return True
        
        return False


def generate_secure_token(length: int = 32) -> str:
    """
    Generate cryptographically secure token.
    
    Args:
        length: Token length
        
    Returns:
        Secure random token
    """
    return secrets.token_urlsafe(length)


def hash_data(data: str, salt: Optional[str] = None) -> str:
    """
    Hash data with optional salt.
    
    Args:
        data: Data to hash
        salt: Optional salt
        
    Returns:
        Hashed data
    """
    if salt:
        data = f"{salt}{data}"
    
    return hashlib.sha256(data.encode()).hexdigest()


def validate_api_key(api_key: str) -> bool:
    """
    Validate API key format.
    
    Args:
        api_key: API key to validate
        
    Returns:
        True if valid format
    """
    if not api_key or not isinstance(api_key, str):
        return False
    
    # API key should be at least 32 characters and contain alphanumeric chars
    return len(api_key) >= 32 and api_key.replace('_', '').replace('-', '').isalnum()

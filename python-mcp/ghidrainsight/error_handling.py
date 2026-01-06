"""Enhanced error handling and logging utilities."""

import logging
import traceback
import sys
from typing import Optional, Dict, Any, Callable
from functools import wraps
from datetime import datetime
import asyncio
from enum import Enum


class ErrorSeverity(Enum):
    """Error severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class GhidraInsightError(Exception):
    """Base exception for GhidraInsight."""
    
    def __init__(self, message: str, severity: ErrorSeverity = ErrorSeverity.MEDIUM, 
                 error_code: Optional[str] = None, context: Optional[Dict[str, Any]] = None):
        """
        Initialize GhidraInsight error.
        
        Args:
            message: Error message
            severity: Error severity
            error_code: Optional error code
            context: Additional context information
        """
        super().__init__(message)
        self.message = message
        self.severity = severity
        self.error_code = error_code
        self.context = context or {}
        self.timestamp = datetime.utcnow()


class ValidationError(GhidraInsightError):
    """Input validation error."""
    
    def __init__(self, message: str, field: Optional[str] = None, **kwargs):
        super().__init__(message, ErrorSeverity.LOW, "VALIDATION_ERROR", **kwargs)
        self.field = field


class SecurityError(GhidraInsightError):
    """Security-related error."""
    
    def __init__(self, message: str, **kwargs):
        super().__init__(message, ErrorSeverity.HIGH, "SECURITY_ERROR", **kwargs)


class AnalysisError(GhidraInsightError):
    """Analysis-related error."""
    
    def __init__(self, message: str, binary_path: Optional[str] = None, **kwargs):
        super().__init__(message, ErrorSeverity.MEDIUM, "ANALYSIS_ERROR", **kwargs)
        self.binary_path = binary_path


class ConfigurationError(GhidraInsightError):
    """Configuration-related error."""
    
    def __init__(self, message: str, config_key: Optional[str] = None, **kwargs):
        super().__init__(message, ErrorSeverity.HIGH, "CONFIG_ERROR", **kwargs)
        self.config_key = config_key


class ErrorHandler:
    """Centralized error handling and logging."""
    
    def __init__(self, logger_name: str = __name__):
        """
        Initialize error handler.
        
        Args:
            logger_name: Logger name to use
        """
        self.logger = logging.getLogger(logger_name)
        self.error_counts = {}
        self.last_errors = {}
    
    def handle_error(self, error: Exception, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Handle and log error with context.
        
        Args:
            error: Exception to handle
            context: Additional context
            
        Returns:
            Error information dictionary
        """
        error_type = type(error).__name__
        error_msg = str(error)
        
        # Count errors
        self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1
        self.last_errors[error_type] = datetime.utcnow()
        
        # Create error info
        error_info = {
            "type": error_type,
            "message": error_msg,
            "timestamp": datetime.utcnow().isoformat(),
            "context": context or {},
            "count": self.error_counts[error_type]
        }
        
        # Add severity if it's a GhidraInsight error
        if isinstance(error, GhidraInsightError):
            error_info.update({
                "severity": error.severity.value,
                "error_code": error.error_code,
                "error_context": error.context
            })
        
        # Log based on severity
        if isinstance(error, GhidraInsightError):
            if error.severity == ErrorSeverity.CRITICAL:
                self.logger.critical(f"Critical error: {error_msg}", exc_info=True, extra=error_info)
            elif error.severity == ErrorSeverity.HIGH:
                self.logger.error(f"High severity error: {error_msg}", exc_info=True, extra=error_info)
            elif error.severity == ErrorSeverity.MEDIUM:
                self.logger.warning(f"Medium severity error: {error_msg}", extra=error_info)
            else:
                self.logger.info(f"Low severity error: {error_msg}", extra=error_info)
        else:
            self.logger.error(f"Unhandled exception: {error_msg}", exc_info=True, extra=error_info)
        
        return error_info
    
    def get_error_stats(self) -> Dict[str, Any]:
        """Get error statistics."""
        return {
            "error_counts": self.error_counts,
            "last_errors": {k: v.isoformat() for k, v in self.last_errors.items()},
            "total_errors": sum(self.error_counts.values())
        }


def safe_execute(
    func: Callable,
    default_return: Any = None,
    error_handler: Optional[ErrorHandler] = None,
    context: Optional[Dict[str, Any]] = None
) -> Callable:
    """
    Decorator for safe function execution with error handling.
    
    Args:
        func: Function to decorate
        default_return: Default return value on error
        error_handler: Error handler instance
        context: Additional context
        
    Returns:
        Decorated function
    """
    @wraps(func)
    async def async_wrapper(*args, **kwargs):
        """Async wrapper."""
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            if error_handler:
                error_handler.handle_error(e, context)
            return default_return
    
    @wraps(func)
    def sync_wrapper(*args, **kwargs):
        """Sync wrapper."""
        try:
            return func(*args, **kwargs)
        except Exception as e:
            if error_handler:
                error_handler.handle_error(e, context)
            return default_return
    
    # Return appropriate wrapper based on function type
    if asyncio.iscoroutinefunction(func):
        return async_wrapper
    else:
        return sync_wrapper


def retry_on_failure(
    max_retries: int = 3,
    delay: float = 1.0,
    backoff_factor: float = 2.0,
    exceptions: tuple = (Exception,)
) -> Callable:
    """
    Decorator for retrying failed operations.
    
    Args:
        max_retries: Maximum number of retries
        delay: Initial delay between retries
        backoff_factor: Multiplier for delay on each retry
        exceptions: Exception types to retry on
        
    Returns:
        Decorated function
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            """Async wrapper with retry logic."""
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    
                    if attempt < max_retries:
                        wait_time = delay * (backoff_factor ** attempt)
                        await asyncio.sleep(wait_time)
                        continue
                    else:
                        raise last_exception
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            """Sync wrapper with retry logic."""
            import time
            
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    
                    if attempt < max_retries:
                        wait_time = delay * (backoff_factor ** attempt)
                        time.sleep(wait_time)
                        continue
                    else:
                        raise last_exception
        
        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


def validate_inputs(**validators) -> Callable:
    """
    Decorator for input validation.
    
    Args:
        **validators: Mapping of parameter names to validator functions
        
    Returns:
        Decorated function
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            """Wrapper with input validation."""
            # Get function signature
            import inspect
            sig = inspect.signature(func)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()
            
            # Validate inputs
            for param_name, validator in validators.items():
                if param_name in bound_args.arguments:
                    value = bound_args.arguments[param_name]
                    if not validator(value):
                        raise ValidationError(
                            f"Invalid value for parameter '{param_name}': {value}",
                            field=param_name
                        )
            
            return func(*args, **kwargs)
        
        return wrapper
    
    return decorator


class CircuitBreaker:
    """Circuit breaker pattern for fault tolerance."""
    
    def __init__(self, failure_threshold: int = 5, recovery_timeout: float = 60.0):
        """
        Initialize circuit breaker.
        
        Args:
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Time to wait before trying to close circuit
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
    
    def __call__(self, func: Callable) -> Callable:
        """Decorator implementation."""
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            """Async wrapper with circuit breaker."""
            if self.state == "OPEN":
                if self._should_attempt_reset():
                    self.state = "HALF_OPEN"
                else:
                    raise GhidraInsightError(
                        "Circuit breaker is OPEN",
                        ErrorSeverity.HIGH,
                        "CIRCUIT_BREAKER_OPEN"
                    )
            
            try:
                result = await func(*args, **kwargs)
                self._on_success()
                return result
            except Exception as e:
                self._on_failure()
                raise
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            """Sync wrapper with circuit breaker."""
            if self.state == "OPEN":
                if self._should_attempt_reset():
                    self.state = "HALF_OPEN"
                else:
                    raise GhidraInsightError(
                        "Circuit breaker is OPEN",
                        ErrorSeverity.HIGH,
                        "CIRCUIT_BREAKER_OPEN"
                    )
            
            try:
                result = func(*args, **kwargs)
                self._on_success()
                return result
            except Exception as e:
                self._on_failure()
                raise
        
        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    def _should_attempt_reset(self) -> bool:
        """Check if circuit breaker should attempt to reset."""
        import time
        return (
            self.state == "OPEN" and
            self.last_failure_time and
            time.time() - self.last_failure_time >= self.recovery_timeout
        )
    
    def _on_success(self):
        """Handle successful operation."""
        self.failure_count = 0
        self.state = "CLOSED"
    
    def _on_failure(self):
        """Handle failed operation."""
        import time
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.failure_threshold:
            self.state = "OPEN"


# Global error handler instance
global_error_handler = ErrorHandler("ghidrainsight")


def setup_exception_logging():
    """Setup global exception logging."""
    def handle_exception(exc_type, exc_value, exc_traceback):
        """Handle uncaught exceptions."""
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        
        global_error_handler.handle_error(exc_value, {
            "exc_type": exc_type.__name__,
            "uncaught": True
        })
    
    sys.excepthook = handle_exception

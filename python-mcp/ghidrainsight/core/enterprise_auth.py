"""
Enterprise Authentication Module for GhidraInsight

This module provides enterprise-grade authentication and authorization capabilities,
including SAML SSO, LDAP/Active Directory integration, multi-factor authentication,
and fine-grained role-based access control.

Author: GhidraInsight Team
License: Apache 2.0
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class AuthMethod(Enum):
    """Authentication methods"""

    LOCAL = "local"
    SAML = "saml"
    LDAP = "ldap"
    OAUTH2 = "oauth2"
    API_KEY = "api_key"
    JWT = "jwt"


class UserRole(Enum):
    """User roles for RBAC"""

    ADMIN = "admin"
    ANALYST = "analyst"
    DEVELOPER = "developer"
    VIEWER = "viewer"
    AUDITOR = "auditor"
    GUEST = "guest"


class Permission(Enum):
    """Fine-grained permissions"""

    # Analysis permissions
    ANALYZE_BINARY = "analyze:binary"
    VIEW_ANALYSIS = "view:analysis"
    DELETE_ANALYSIS = "delete:analysis"
    EXPORT_ANALYSIS = "export:analysis"

    # System permissions
    MANAGE_USERS = "manage:users"
    MANAGE_ROLES = "manage:roles"
    MANAGE_SETTINGS = "manage:settings"
    VIEW_AUDIT_LOG = "view:audit_log"

    # API permissions
    API_READ = "api:read"
    API_WRITE = "api:write"
    API_ADMIN = "api:admin"

    # Project permissions
    CREATE_PROJECT = "create:project"
    DELETE_PROJECT = "delete:project"
    SHARE_PROJECT = "share:project"


@dataclass
class User:
    """User account information"""

    user_id: str
    username: str
    email: str
    full_name: str
    roles: List[UserRole] = field(default_factory=list)
    permissions: Set[Permission] = field(default_factory=set)
    auth_method: AuthMethod = AuthMethod.LOCAL
    mfa_enabled: bool = False
    mfa_secret: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    last_login: Optional[float] = None
    is_active: bool = True
    is_locked: bool = False
    failed_login_attempts: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Session:
    """User session information"""

    session_id: str
    user_id: str
    username: str
    auth_method: AuthMethod
    created_at: float
    expires_at: float
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    mfa_verified: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class APIKey:
    """API key for programmatic access"""

    key_id: str
    key_hash: str
    user_id: str
    name: str
    permissions: Set[Permission] = field(default_factory=set)
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    last_used: Optional[float] = None
    is_active: bool = True


@dataclass
class AuditLog:
    """Audit log entry"""

    log_id: str
    timestamp: float
    user_id: str
    username: str
    action: str
    resource: str
    result: str  # "success", "failure", "denied"
    ip_address: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthConfig:
    """Authentication configuration"""

    # Session settings
    session_timeout: int = 3600  # 1 hour
    session_absolute_timeout: int = 86400  # 24 hours
    max_sessions_per_user: int = 5

    # Password policy
    min_password_length: int = 12
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_numbers: bool = True
    require_special_chars: bool = True
    password_expiry_days: int = 90

    # Account security
    max_failed_login_attempts: int = 5
    account_lockout_duration: int = 1800  # 30 minutes
    enable_mfa: bool = True

    # SAML settings
    saml_enabled: bool = False
    saml_sp_entity_id: Optional[str] = None
    saml_sp_acs_url: Optional[str] = None
    saml_idp_entity_id: Optional[str] = None
    saml_idp_sso_url: Optional[str] = None
    saml_idp_cert: Optional[str] = None

    # LDAP settings
    ldap_enabled: bool = False
    ldap_server: Optional[str] = None
    ldap_port: int = 389
    ldap_use_ssl: bool = True
    ldap_base_dn: Optional[str] = None
    ldap_bind_dn: Optional[str] = None
    ldap_bind_password: Optional[str] = None
    ldap_user_filter: str = "(uid={username})"
    ldap_group_filter: str = "(member={user_dn})"

    # OAuth2 settings
    oauth2_enabled: bool = False
    oauth2_client_id: Optional[str] = None
    oauth2_client_secret: Optional[str] = None
    oauth2_authorize_url: Optional[str] = None
    oauth2_token_url: Optional[str] = None
    oauth2_userinfo_url: Optional[str] = None

    # Audit settings
    enable_audit_log: bool = True
    audit_log_retention_days: int = 365


class EnterpriseAuthenticator:
    """
    Enterprise authentication and authorization manager.
    """

    def __init__(self, config: Optional[AuthConfig] = None):
        self.config = config or AuthConfig()
        self.users: Dict[str, User] = {}
        self.sessions: Dict[str, Session] = {}
        self.api_keys: Dict[str, APIKey] = {}
        self.audit_logs: List[AuditLog] = []
        self.role_permissions = self._initialize_role_permissions()

        # Initialize backend clients
        self.ldap_client = None
        self.saml_client = None

        if self.config.ldap_enabled:
            self._initialize_ldap()

        if self.config.saml_enabled:
            self._initialize_saml()

    def _initialize_role_permissions(self) -> Dict[UserRole, Set[Permission]]:
        """Initialize default role-permission mappings"""
        return {
            UserRole.ADMIN: {
                # Full access
                Permission.ANALYZE_BINARY,
                Permission.VIEW_ANALYSIS,
                Permission.DELETE_ANALYSIS,
                Permission.EXPORT_ANALYSIS,
                Permission.MANAGE_USERS,
                Permission.MANAGE_ROLES,
                Permission.MANAGE_SETTINGS,
                Permission.VIEW_AUDIT_LOG,
                Permission.API_READ,
                Permission.API_WRITE,
                Permission.API_ADMIN,
                Permission.CREATE_PROJECT,
                Permission.DELETE_PROJECT,
                Permission.SHARE_PROJECT,
            },
            UserRole.ANALYST: {
                Permission.ANALYZE_BINARY,
                Permission.VIEW_ANALYSIS,
                Permission.EXPORT_ANALYSIS,
                Permission.API_READ,
                Permission.API_WRITE,
                Permission.CREATE_PROJECT,
                Permission.SHARE_PROJECT,
            },
            UserRole.DEVELOPER: {
                Permission.ANALYZE_BINARY,
                Permission.VIEW_ANALYSIS,
                Permission.EXPORT_ANALYSIS,
                Permission.API_READ,
                Permission.API_WRITE,
                Permission.CREATE_PROJECT,
            },
            UserRole.VIEWER: {
                Permission.VIEW_ANALYSIS,
                Permission.API_READ,
            },
            UserRole.AUDITOR: {
                Permission.VIEW_ANALYSIS,
                Permission.VIEW_AUDIT_LOG,
                Permission.API_READ,
            },
            UserRole.GUEST: {
                Permission.VIEW_ANALYSIS,
            },
        }

    def _initialize_ldap(self):
        """Initialize LDAP/Active Directory connection"""
        try:
            import ldap3

            server = ldap3.Server(
                self.config.ldap_server,
                port=self.config.ldap_port,
                use_ssl=self.config.ldap_use_ssl,
            )

            self.ldap_client = ldap3.Connection(
                server,
                user=self.config.ldap_bind_dn,
                password=self.config.ldap_bind_password,
            )

            if not self.ldap_client.bind():
                logger.error("Failed to bind to LDAP server")
                self.ldap_client = None
            else:
                logger.info("LDAP client initialized successfully")

        except ImportError:
            logger.error("ldap3 not installed. Install with: pip install ldap3")
        except Exception as e:
            logger.error(f"Failed to initialize LDAP: {e}")

    def _initialize_saml(self):
        """Initialize SAML SSO"""
        try:
            from onelogin.saml2.auth import OneLogin_Saml2_Auth
            from onelogin.saml2.settings import OneLogin_Saml2_Settings

            saml_settings = {
                "sp": {
                    "entityId": self.config.saml_sp_entity_id,
                    "assertionConsumerService": {
                        "url": self.config.saml_sp_acs_url,
                        "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                    },
                },
                "idp": {
                    "entityId": self.config.saml_idp_entity_id,
                    "singleSignOnService": {
                        "url": self.config.saml_idp_sso_url,
                        "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                    },
                    "x509cert": self.config.saml_idp_cert,
                },
            }

            self.saml_client = OneLogin_Saml2_Settings(saml_settings)
            logger.info("SAML client initialized successfully")

        except ImportError:
            logger.error(
                "python3-saml not installed. Install with: pip install python3-saml"
            )
        except Exception as e:
            logger.error(f"Failed to initialize SAML: {e}")

    def authenticate(
        self,
        username: str,
        password: Optional[str] = None,
        auth_method: AuthMethod = AuthMethod.LOCAL,
        mfa_code: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Tuple[bool, Optional[Session], Optional[str]]:
        """
        Authenticate a user.

        Args:
            username: Username
            password: Password (for local/LDAP auth)
            auth_method: Authentication method
            mfa_code: MFA code if MFA is enabled
            ip_address: Client IP address
            user_agent: Client user agent

        Returns:
            Tuple of (success, session, error_message)
        """
        # Check if user exists and is active
        user = self.users.get(username)

        if not user or not user.is_active:
            self._audit_log(
                username,
                "login",
                "user",
                "failure",
                ip_address,
                {"reason": "user_not_found"},
            )
            return False, None, "Invalid credentials"

        if user.is_locked:
            self._audit_log(
                username,
                "login",
                "user",
                "denied",
                ip_address,
                {"reason": "account_locked"},
            )
            return False, None, "Account is locked"

        # Authenticate based on method
        success = False

        if auth_method == AuthMethod.LOCAL:
            success = self._authenticate_local(user, password)
        elif auth_method == AuthMethod.LDAP:
            success = self._authenticate_ldap(username, password)
        elif auth_method == AuthMethod.SAML:
            # SAML authentication is handled separately via SSO flow
            return False, None, "Use SAML SSO flow"
        else:
            return False, None, "Unsupported authentication method"

        if not success:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= self.config.max_failed_login_attempts:
                user.is_locked = True
                logger.warning(
                    f"Account locked due to failed login attempts: {username}"
                )

            self._audit_log(
                username,
                "login",
                "user",
                "failure",
                ip_address,
                {"reason": "invalid_credentials"},
            )
            return False, None, "Invalid credentials"

        # Reset failed attempts on successful authentication
        user.failed_login_attempts = 0

        # Check MFA if enabled
        if user.mfa_enabled:
            if not mfa_code:
                return False, None, "MFA code required"

            if not self._verify_mfa(user, mfa_code):
                self._audit_log(
                    username,
                    "login",
                    "user",
                    "failure",
                    ip_address,
                    {"reason": "invalid_mfa"},
                )
                return False, None, "Invalid MFA code"

        # Create session
        session = self._create_session(
            user, auth_method, ip_address, user_agent, mfa_verified=user.mfa_enabled
        )

        user.last_login = time.time()

        self._audit_log(username, "login", "user", "success", ip_address)

        logger.info(f"User authenticated successfully: {username}")
        return True, session, None

    def _authenticate_local(self, user: User, password: Optional[str]) -> bool:
        """Authenticate using local password"""
        if not password:
            return False

        # In production, passwords should be hashed with bcrypt/argon2
        stored_password_hash = user.metadata.get("password_hash")
        if not stored_password_hash:
            return False

        # Simple comparison for demonstration
        # In production: use bcrypt.checkpw() or similar
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        return hmac.compare_digest(stored_password_hash, password_hash)

    def _authenticate_ldap(self, username: str, password: Optional[str]) -> bool:
        """Authenticate using LDAP/Active Directory"""
        if not self.ldap_client or not password:
            return False

        try:
            import ldap3

            # Search for user
            user_filter = self.config.ldap_user_filter.format(username=username)
            self.ldap_client.search(
                search_base=self.config.ldap_base_dn,
                search_filter=user_filter,
                attributes=["cn", "mail", "memberOf"],
            )

            if not self.ldap_client.entries:
                return False

            user_entry = self.ldap_client.entries[0]
            user_dn = user_entry.entry_dn

            # Attempt to bind with user credentials
            user_conn = ldap3.Connection(
                self.ldap_client.server, user=user_dn, password=password
            )

            if user_conn.bind():
                user_conn.unbind()
                logger.info(f"LDAP authentication successful: {username}")
                return True

        except Exception as e:
            logger.error(f"LDAP authentication error: {e}")

        return False

    def _verify_mfa(self, user: User, code: str) -> bool:
        """Verify MFA code (TOTP)"""
        if not user.mfa_secret:
            return False

        try:
            import pyotp

            totp = pyotp.TOTP(user.mfa_secret)
            return totp.verify(code, valid_window=1)

        except ImportError:
            logger.error("pyotp not installed. Install with: pip install pyotp")
            return False
        except Exception as e:
            logger.error(f"MFA verification error: {e}")
            return False

    def _create_session(
        self,
        user: User,
        auth_method: AuthMethod,
        ip_address: Optional[str],
        user_agent: Optional[str],
        mfa_verified: bool = False,
    ) -> Session:
        """Create a new session"""
        session_id = secrets.token_urlsafe(32)
        now = time.time()

        session = Session(
            session_id=session_id,
            user_id=user.user_id,
            username=user.username,
            auth_method=auth_method,
            created_at=now,
            expires_at=now + self.config.session_timeout,
            ip_address=ip_address,
            user_agent=user_agent,
            mfa_verified=mfa_verified,
        )

        self.sessions[session_id] = session

        # Enforce max sessions per user
        user_sessions = [s for s in self.sessions.values() if s.user_id == user.user_id]
        if len(user_sessions) > self.config.max_sessions_per_user:
            # Remove oldest session
            oldest = min(user_sessions, key=lambda s: s.created_at)
            del self.sessions[oldest.session_id]

        return session

    def validate_session(self, session_id: str) -> Tuple[bool, Optional[User]]:
        """Validate a session and return user if valid"""
        session = self.sessions.get(session_id)

        if not session:
            return False, None

        # Check if expired
        if time.time() > session.expires_at:
            del self.sessions[session_id]
            return False, None

        # Get user
        user = self.users.get(session.user_id)
        if not user or not user.is_active:
            return False, None

        # Extend session
        session.expires_at = time.time() + self.config.session_timeout

        return True, user

    def logout(self, session_id: str, username: str, ip_address: Optional[str] = None):
        """Logout user and invalidate session"""
        if session_id in self.sessions:
            del self.sessions[session_id]
            self._audit_log(username, "logout", "user", "success", ip_address)
            logger.info(f"User logged out: {username}")

    def validate_api_key(
        self, api_key: str
    ) -> Tuple[bool, Optional[User], Optional[APIKey]]:
        """Validate an API key"""
        # Hash the provided key
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        # Find matching API key
        for key_id, key_obj in self.api_keys.items():
            if hmac.compare_digest(key_obj.key_hash, key_hash):
                if not key_obj.is_active:
                    return False, None, None

                # Check expiration
                if key_obj.expires_at and time.time() > key_obj.expires_at:
                    key_obj.is_active = False
                    return False, None, None

                # Update last used
                key_obj.last_used = time.time()

                # Get user
                user = self.users.get(key_obj.user_id)
                if user and user.is_active:
                    return True, user, key_obj

        return False, None, None

    def create_api_key(
        self,
        user_id: str,
        name: str,
        permissions: Optional[Set[Permission]] = None,
        expires_in_days: Optional[int] = None,
    ) -> Tuple[str, APIKey]:
        """Create a new API key"""
        # Generate random key
        api_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        key_id = f"key_{secrets.token_hex(8)}"

        expires_at = None
        if expires_in_days:
            expires_at = time.time() + (expires_in_days * 86400)

        key_obj = APIKey(
            key_id=key_id,
            key_hash=key_hash,
            user_id=user_id,
            name=name,
            permissions=permissions or set(),
            expires_at=expires_at,
        )

        self.api_keys[key_id] = key_obj

        user = self.users.get(user_id)
        if user:
            self._audit_log(
                user.username,
                "create_api_key",
                "api_key",
                "success",
                None,
                {"key_id": key_id},
            )

        return api_key, key_obj

    def revoke_api_key(self, key_id: str, username: str):
        """Revoke an API key"""
        if key_id in self.api_keys:
            self.api_keys[key_id].is_active = False
            self._audit_log(
                username,
                "revoke_api_key",
                "api_key",
                "success",
                None,
                {"key_id": key_id},
            )
            logger.info(f"API key revoked: {key_id}")

    def check_permission(
        self, user: User, permission: Permission, api_key: Optional[APIKey] = None
    ) -> bool:
        """Check if user has a specific permission"""
        # Check API key permissions if provided
        if api_key:
            return permission in api_key.permissions

        # Check user permissions (direct + role-based)
        if permission in user.permissions:
            return True

        # Check role permissions
        for role in user.roles:
            role_perms = self.role_permissions.get(role, set())
            if permission in role_perms:
                return True

        return False

    def add_user(
        self,
        username: str,
        email: str,
        full_name: str,
        password: Optional[str] = None,
        roles: Optional[List[UserRole]] = None,
        auth_method: AuthMethod = AuthMethod.LOCAL,
    ) -> User:
        """Add a new user"""
        user_id = f"user_{secrets.token_hex(8)}"

        user = User(
            user_id=user_id,
            username=username,
            email=email,
            full_name=full_name,
            roles=roles or [UserRole.VIEWER],
            auth_method=auth_method,
        )

        # Compute permissions from roles
        for role in user.roles:
            user.permissions.update(self.role_permissions.get(role, set()))

        # Hash password if provided
        if password and auth_method == AuthMethod.LOCAL:
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            user.metadata["password_hash"] = password_hash

        self.users[username] = user
        logger.info(f"User created: {username}")

        return user

    def enable_mfa(self, username: str) -> Optional[str]:
        """Enable MFA for a user and return secret"""
        user = self.users.get(username)
        if not user:
            return None

        try:
            import pyotp

            secret = pyotp.random_base32()
            user.mfa_secret = secret
            user.mfa_enabled = True

            logger.info(f"MFA enabled for user: {username}")
            return secret

        except ImportError:
            logger.error("pyotp not installed")
            return None

    def _audit_log(
        self,
        username: str,
        action: str,
        resource: str,
        result: str,
        ip_address: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        """Create an audit log entry"""
        if not self.config.enable_audit_log:
            return

        user = self.users.get(username)
        user_id = user.user_id if user else "unknown"

        log = AuditLog(
            log_id=f"log_{int(time.time() * 1000)}_{secrets.token_hex(4)}",
            timestamp=time.time(),
            user_id=user_id,
            username=username,
            action=action,
            resource=resource,
            result=result,
            ip_address=ip_address,
            details=details or {},
        )

        self.audit_logs.append(log)

        # Cleanup old logs
        cutoff = time.time() - (self.config.audit_log_retention_days * 86400)
        self.audit_logs = [log for log in self.audit_logs if log.timestamp > cutoff]

    def get_audit_logs(
        self,
        username: Optional[str] = None,
        action: Optional[str] = None,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        limit: int = 100,
    ) -> List[AuditLog]:
        """Query audit logs"""
        filtered_logs = self.audit_logs

        if username:
            filtered_logs = [log for log in filtered_logs if log.username == username]

        if action:
            filtered_logs = [log for log in filtered_logs if log.action == action]

        if start_time:
            filtered_logs = [
                log for log in filtered_logs if log.timestamp >= start_time
            ]

        if end_time:
            filtered_logs = [log for log in filtered_logs if log.timestamp <= end_time]

        # Sort by timestamp (newest first)
        filtered_logs.sort(key=lambda log: log.timestamp, reverse=True)

        return filtered_logs[:limit]

    def export_audit_logs(self, output_path: str, format: str = "json"):
        """Export audit logs to file"""
        data = [
            {
                "log_id": log.log_id,
                "timestamp": log.timestamp,
                "datetime": datetime.fromtimestamp(log.timestamp).isoformat(),
                "user_id": log.user_id,
                "username": log.username,
                "action": log.action,
                "resource": log.resource,
                "result": log.result,
                "ip_address": log.ip_address,
                "details": log.details,
            }
            for log in self.audit_logs
        ]

        if format == "json":
            with open(output_path, "w") as f:
                json.dump(data, f, indent=2)
        else:
            raise ValueError(f"Unsupported format: {format}")

        logger.info(f"Audit logs exported to {output_path}")


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Create authenticator
    config = AuthConfig(
        ldap_enabled=False,
        saml_enabled=False,
        enable_mfa=True,
        enable_audit_log=True,
    )
    auth = EnterpriseAuthenticator(config)

    # Add test user
    user = auth.add_user(
        username="alice",
        email="alice@example.com",
        full_name="Alice Anderson",
        password="SecurePassword123!",
        roles=[UserRole.ANALYST],
    )

    # Authenticate
    success, session, error = auth.authenticate("alice", "SecurePassword123!")
    if success:
        print(f"Authentication successful: {session.session_id}")

        # Check permission
        can_analyze = auth.check_permission(user, Permission.ANALYZE_BINARY)
        print(f"Can analyze binary: {can_analyze}")

        # Create API key
        api_key, key_obj = auth.create_api_key(
            user.user_id, "My API Key", {Permission.API_READ, Permission.API_WRITE}
        )
        print(f"API Key: {api_key}")

        # Logout
        auth.logout(session.session_id, "alice")
    else:
        print(f"Authentication failed: {error}")

    # Export audit logs
    auth.export_audit_logs("audit_logs.json")

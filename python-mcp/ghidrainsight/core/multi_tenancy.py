"""
Multi-Tenancy Support Module for GhidraInsight

This module provides comprehensive multi-tenancy support for enterprise deployments,
including tenant management, data isolation, resource quotas, and compliance features.

Author: GhidraInsight Team
License: Apache 2.0
"""

import hashlib
import json
import logging
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class TenantStatus(Enum):
    """Tenant account status"""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    TRIAL = "trial"
    PENDING = "pending"
    TERMINATED = "terminated"


class TenantTier(Enum):
    """Tenant subscription tiers"""

    FREE = "free"
    STARTER = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"
    CUSTOM = "custom"


class ResourceType(Enum):
    """Types of resources that can be limited"""

    ANALYSES = "analyses"
    STORAGE = "storage"
    API_CALLS = "api_calls"
    USERS = "users"
    PROJECTS = "projects"
    CONCURRENT_JOBS = "concurrent_jobs"


class IsolationLevel(Enum):
    """Data isolation levels"""

    SHARED = "shared"  # Shared database with row-level security
    SCHEMA = "schema"  # Separate database schema per tenant
    DATABASE = "database"  # Separate database per tenant
    INSTANCE = "instance"  # Separate application instance


@dataclass
class ResourceQuota:
    """Resource quota for a tenant"""

    resource_type: ResourceType
    limit: int  # -1 for unlimited
    current_usage: int = 0
    soft_limit: int = 0  # Warning threshold
    reset_period: Optional[int] = None  # Seconds, None for no reset


@dataclass
class TenantConfig:
    """Tenant-specific configuration"""

    # Feature flags
    enable_advanced_analysis: bool = True
    enable_ml_detection: bool = True
    enable_gpu_acceleration: bool = False
    enable_distributed_analysis: bool = False
    enable_api_access: bool = True
    enable_webhook_notifications: bool = False

    # Security settings
    enforce_mfa: bool = False
    allowed_ip_ranges: List[str] = field(default_factory=list)
    session_timeout: int = 3600
    password_policy: Dict[str, Any] = field(default_factory=dict)

    # Data retention
    data_retention_days: int = 365
    audit_log_retention_days: int = 90
    auto_delete_old_data: bool = True

    # Compliance
    data_residency_region: Optional[str] = None
    encryption_at_rest: bool = True
    encryption_in_transit: bool = True
    compliance_frameworks: List[str] = field(default_factory=list)  # GDPR, HIPAA, etc.

    # Integration
    custom_branding: bool = False
    custom_domain: Optional[str] = None
    webhook_url: Optional[str] = None
    sso_enabled: bool = False

    # Performance
    max_binary_size: int = 1024 * 1024 * 1024  # 1GB default
    concurrent_analysis_limit: int = 10
    api_rate_limit: int = 1000  # requests per hour

    # Custom settings
    custom_settings: Dict[str, Any] = field(default_factory=dict)


@dataclass
class UsageMetrics:
    """Usage metrics for a tenant"""

    analyses_count: int = 0
    storage_bytes: int = 0
    api_calls_count: int = 0
    active_users: int = 0
    total_users: int = 0
    projects_count: int = 0
    peak_concurrent_jobs: int = 0

    # Time-series data
    daily_analyses: List[int] = field(default_factory=list)
    daily_api_calls: List[int] = field(default_factory=list)
    daily_storage: List[int] = field(default_factory=list)

    last_updated: float = field(default_factory=time.time)


@dataclass
class BillingInfo:
    """Billing information for a tenant"""

    billing_email: str
    billing_address: Dict[str, str] = field(default_factory=dict)
    payment_method: Optional[str] = None
    subscription_start: float = field(default_factory=time.time)
    subscription_end: Optional[float] = None
    billing_cycle: str = "monthly"  # monthly, annual
    next_billing_date: Optional[float] = None
    total_cost: float = 0.0
    currency: str = "USD"


@dataclass
class Tenant:
    """Represents a single tenant in the multi-tenant system"""

    tenant_id: str
    tenant_name: str
    subdomain: str
    status: TenantStatus
    tier: TenantTier

    # Contact information
    admin_email: str
    admin_name: str
    company_name: Optional[str] = None
    contact_phone: Optional[str] = None

    # Configuration
    config: TenantConfig = field(default_factory=TenantConfig)

    # Resource management
    quotas: Dict[ResourceType, ResourceQuota] = field(default_factory=dict)
    usage: UsageMetrics = field(default_factory=UsageMetrics)

    # Billing
    billing_info: Optional[BillingInfo] = None

    # Isolation
    isolation_level: IsolationLevel = IsolationLevel.SHARED
    database_name: Optional[str] = None
    schema_name: Optional[str] = None

    # Metadata
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    trial_expires_at: Optional[float] = None
    suspended_reason: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TenantUser:
    """User within a tenant context"""

    user_id: str
    tenant_id: str
    username: str
    email: str
    roles: List[str] = field(default_factory=list)
    is_tenant_admin: bool = False
    created_at: float = field(default_factory=time.time)
    last_active: Optional[float] = None


class MultiTenancyManager:
    """
    Multi-tenancy manager for GhidraInsight.
    Handles tenant lifecycle, resource isolation, and quota management.
    """

    def __init__(self):
        self.tenants: Dict[str, Tenant] = {}
        self.tenant_users: Dict[str, List[TenantUser]] = {}  # tenant_id -> users
        self.subdomain_map: Dict[str, str] = {}  # subdomain -> tenant_id
        self.tier_quotas = self._initialize_tier_quotas()

    def _initialize_tier_quotas(self) -> Dict[TenantTier, Dict[ResourceType, int]]:
        """Initialize default quotas for each tier"""
        return {
            TenantTier.FREE: {
                ResourceType.ANALYSES: 100,
                ResourceType.STORAGE: 1024 * 1024 * 1024,  # 1GB
                ResourceType.API_CALLS: 1000,
                ResourceType.USERS: 3,
                ResourceType.PROJECTS: 5,
                ResourceType.CONCURRENT_JOBS: 1,
            },
            TenantTier.STARTER: {
                ResourceType.ANALYSES: 1000,
                ResourceType.STORAGE: 10 * 1024 * 1024 * 1024,  # 10GB
                ResourceType.API_CALLS: 10000,
                ResourceType.USERS: 10,
                ResourceType.PROJECTS: 25,
                ResourceType.CONCURRENT_JOBS: 3,
            },
            TenantTier.PROFESSIONAL: {
                ResourceType.ANALYSES: 10000,
                ResourceType.STORAGE: 100 * 1024 * 1024 * 1024,  # 100GB
                ResourceType.API_CALLS: 100000,
                ResourceType.USERS: 50,
                ResourceType.PROJECTS: 100,
                ResourceType.CONCURRENT_JOBS: 10,
            },
            TenantTier.ENTERPRISE: {
                ResourceType.ANALYSES: -1,  # Unlimited
                ResourceType.STORAGE: -1,
                ResourceType.API_CALLS: -1,
                ResourceType.USERS: -1,
                ResourceType.PROJECTS: -1,
                ResourceType.CONCURRENT_JOBS: 50,
            },
            TenantTier.CUSTOM: {
                ResourceType.ANALYSES: -1,
                ResourceType.STORAGE: -1,
                ResourceType.API_CALLS: -1,
                ResourceType.USERS: -1,
                ResourceType.PROJECTS: -1,
                ResourceType.CONCURRENT_JOBS: -1,
            },
        }

    def create_tenant(
        self,
        tenant_name: str,
        subdomain: str,
        admin_email: str,
        admin_name: str,
        tier: TenantTier = TenantTier.FREE,
        isolation_level: IsolationLevel = IsolationLevel.SHARED,
        trial_days: Optional[int] = 30,
    ) -> Tenant:
        """
        Create a new tenant.

        Args:
            tenant_name: Display name for the tenant
            subdomain: Unique subdomain (e.g., 'acme' for acme.ghidrainsight.com)
            admin_email: Email of the tenant administrator
            admin_name: Name of the tenant administrator
            tier: Subscription tier
            isolation_level: Data isolation level
            trial_days: Number of trial days (None for no trial)

        Returns:
            Created Tenant object
        """
        # Validate subdomain
        if subdomain in self.subdomain_map:
            raise ValueError(f"Subdomain already exists: {subdomain}")

        # Generate unique tenant ID
        tenant_id = f"tenant_{secrets.token_hex(12)}"

        # Set trial expiration if applicable
        trial_expires_at = None
        status = TenantStatus.ACTIVE
        if trial_days:
            trial_expires_at = time.time() + (trial_days * 86400)
            status = TenantStatus.TRIAL

        # Create tenant
        tenant = Tenant(
            tenant_id=tenant_id,
            tenant_name=tenant_name,
            subdomain=subdomain,
            status=status,
            tier=tier,
            admin_email=admin_email,
            admin_name=admin_name,
            isolation_level=isolation_level,
            trial_expires_at=trial_expires_at,
        )

        # Set up database isolation
        if isolation_level == IsolationLevel.SCHEMA:
            tenant.schema_name = f"tenant_{subdomain}"
        elif isolation_level == IsolationLevel.DATABASE:
            tenant.database_name = f"ghidra_tenant_{subdomain}"

        # Initialize quotas based on tier
        self._initialize_tenant_quotas(tenant)

        # Store tenant
        self.tenants[tenant_id] = tenant
        self.subdomain_map[subdomain] = tenant_id
        self.tenant_users[tenant_id] = []

        logger.info(
            f"Tenant created: {tenant_name} ({tenant_id}) - "
            f"Tier: {tier.value}, Isolation: {isolation_level.value}"
        )

        return tenant

    def _initialize_tenant_quotas(self, tenant: Tenant):
        """Initialize resource quotas for a tenant based on tier"""
        tier_quotas = self.tier_quotas.get(tenant.tier, {})

        for resource_type, limit in tier_quotas.items():
            quota = ResourceQuota(
                resource_type=resource_type,
                limit=limit,
                soft_limit=int(limit * 0.8) if limit > 0 else 0,
            )
            tenant.quotas[resource_type] = quota

    def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        """Get tenant by ID"""
        return self.tenants.get(tenant_id)

    def get_tenant_by_subdomain(self, subdomain: str) -> Optional[Tenant]:
        """Get tenant by subdomain"""
        tenant_id = self.subdomain_map.get(subdomain)
        if tenant_id:
            return self.tenants.get(tenant_id)
        return None

    def update_tenant(
        self, tenant_id: str, updates: Dict[str, Any]
    ) -> Optional[Tenant]:
        """Update tenant information"""
        tenant = self.tenants.get(tenant_id)
        if not tenant:
            return None

        # Update allowed fields
        allowed_fields = {
            "tenant_name",
            "admin_email",
            "admin_name",
            "company_name",
            "contact_phone",
            "status",
            "tier",
        }

        for field, value in updates.items():
            if field in allowed_fields:
                setattr(tenant, field, value)

        tenant.updated_at = time.time()
        logger.info(f"Tenant updated: {tenant_id}")

        return tenant

    def suspend_tenant(self, tenant_id: str, reason: str):
        """Suspend a tenant account"""
        tenant = self.tenants.get(tenant_id)
        if not tenant:
            raise ValueError(f"Tenant not found: {tenant_id}")

        tenant.status = TenantStatus.SUSPENDED
        tenant.suspended_reason = reason
        tenant.updated_at = time.time()

        logger.warning(f"Tenant suspended: {tenant_id} - Reason: {reason}")

    def reactivate_tenant(self, tenant_id: str):
        """Reactivate a suspended tenant"""
        tenant = self.tenants.get(tenant_id)
        if not tenant:
            raise ValueError(f"Tenant not found: {tenant_id}")

        tenant.status = TenantStatus.ACTIVE
        tenant.suspended_reason = None
        tenant.updated_at = time.time()

        logger.info(f"Tenant reactivated: {tenant_id}")

    def terminate_tenant(self, tenant_id: str):
        """Terminate a tenant (soft delete)"""
        tenant = self.tenants.get(tenant_id)
        if not tenant:
            raise ValueError(f"Tenant not found: {tenant_id}")

        tenant.status = TenantStatus.TERMINATED
        tenant.updated_at = time.time()

        logger.warning(f"Tenant terminated: {tenant_id}")

    def upgrade_tenant(self, tenant_id: str, new_tier: TenantTier):
        """Upgrade or downgrade tenant tier"""
        tenant = self.tenants.get(tenant_id)
        if not tenant:
            raise ValueError(f"Tenant not found: {tenant_id}")

        old_tier = tenant.tier
        tenant.tier = new_tier
        tenant.updated_at = time.time()

        # Update quotas
        self._initialize_tenant_quotas(tenant)

        logger.info(
            f"Tenant tier changed: {tenant_id} - {old_tier.value} -> {new_tier.value}"
        )

    def check_quota(
        self, tenant_id: str, resource_type: ResourceType, amount: int = 1
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if tenant has quota available for a resource.

        Returns:
            Tuple of (allowed, error_message)
        """
        tenant = self.tenants.get(tenant_id)
        if not tenant:
            return False, "Tenant not found"

        if tenant.status != TenantStatus.ACTIVE:
            return False, f"Tenant is {tenant.status.value}"

        quota = tenant.quotas.get(resource_type)
        if not quota:
            return True, None  # No quota configured

        # Unlimited quota
        if quota.limit == -1:
            return True, None

        # Check if over limit
        if quota.current_usage + amount > quota.limit:
            return (
                False,
                f"{resource_type.value} quota exceeded: {quota.current_usage}/{quota.limit}",
            )

        # Check soft limit (warning)
        if quota.soft_limit > 0 and quota.current_usage + amount > quota.soft_limit:
            logger.warning(
                f"Tenant {tenant_id} approaching {resource_type.value} quota limit: "
                f"{quota.current_usage}/{quota.limit}"
            )

        return True, None

    def consume_quota(
        self, tenant_id: str, resource_type: ResourceType, amount: int = 1
    ) -> bool:
        """
        Consume quota for a resource.

        Returns:
            True if successful, False if quota exceeded
        """
        allowed, error = self.check_quota(tenant_id, resource_type, amount)
        if not allowed:
            logger.error(f"Quota check failed for {tenant_id}: {error}")
            return False

        tenant = self.tenants[tenant_id]
        quota = tenant.quotas.get(resource_type)

        if quota and quota.limit != -1:
            quota.current_usage += amount

        return True

    def release_quota(
        self, tenant_id: str, resource_type: ResourceType, amount: int = 1
    ):
        """Release consumed quota (e.g., when deleting a resource)"""
        tenant = self.tenants.get(tenant_id)
        if not tenant:
            return

        quota = tenant.quotas.get(resource_type)
        if quota:
            quota.current_usage = max(0, quota.current_usage - amount)

    def update_usage_metrics(self, tenant_id: str, metrics: Dict[str, Any]) -> bool:
        """Update usage metrics for a tenant"""
        tenant = self.tenants.get(tenant_id)
        if not tenant:
            return False

        usage = tenant.usage

        for metric, value in metrics.items():
            if hasattr(usage, metric):
                setattr(usage, metric, value)

        usage.last_updated = time.time()
        return True

    def get_usage_report(self, tenant_id: str, days: int = 30) -> Dict[str, Any]:
        """Generate usage report for a tenant"""
        tenant = self.tenants.get(tenant_id)
        if not tenant:
            return {}

        report = {
            "tenant_id": tenant_id,
            "tenant_name": tenant.tenant_name,
            "tier": tenant.tier.value,
            "period_days": days,
            "current_usage": {
                "analyses": tenant.usage.analyses_count,
                "storage_gb": tenant.usage.storage_bytes / (1024**3),
                "api_calls": tenant.usage.api_calls_count,
                "active_users": tenant.usage.active_users,
                "projects": tenant.usage.projects_count,
            },
            "quotas": {
                rt.value: {
                    "limit": quota.limit,
                    "current": quota.current_usage,
                    "percentage": (
                        (quota.current_usage / quota.limit * 100)
                        if quota.limit > 0
                        else 0
                    ),
                }
                for rt, quota in tenant.quotas.items()
            },
        }

        return report

    def add_tenant_user(
        self,
        tenant_id: str,
        username: str,
        email: str,
        roles: List[str],
        is_admin: bool = False,
    ) -> Optional[TenantUser]:
        """Add a user to a tenant"""
        tenant = self.tenants.get(tenant_id)
        if not tenant:
            return None

        # Check user quota
        allowed, error = self.check_quota(tenant_id, ResourceType.USERS)
        if not allowed:
            logger.error(f"Cannot add user: {error}")
            return None

        user_id = f"user_{secrets.token_hex(8)}"
        user = TenantUser(
            user_id=user_id,
            tenant_id=tenant_id,
            username=username,
            email=email,
            roles=roles,
            is_tenant_admin=is_admin,
        )

        if tenant_id not in self.tenant_users:
            self.tenant_users[tenant_id] = []

        self.tenant_users[tenant_id].append(user)
        self.consume_quota(tenant_id, ResourceType.USERS)

        logger.info(f"User added to tenant: {username} -> {tenant_id}")

        return user

    def remove_tenant_user(self, tenant_id: str, user_id: str) -> bool:
        """Remove a user from a tenant"""
        if tenant_id not in self.tenant_users:
            return False

        users = self.tenant_users[tenant_id]
        for i, user in enumerate(users):
            if user.user_id == user_id:
                del users[i]
                self.release_quota(tenant_id, ResourceType.USERS)
                logger.info(f"User removed from tenant: {user_id} -> {tenant_id}")
                return True

        return False

    def list_tenants(
        self,
        status: Optional[TenantStatus] = None,
        tier: Optional[TenantTier] = None,
    ) -> List[Tenant]:
        """List tenants with optional filtering"""
        tenants = list(self.tenants.values())

        if status:
            tenants = [t for t in tenants if t.status == status]

        if tier:
            tenants = [t for t in tenants if t.tier == tier]

        return tenants

    def check_trial_expiration(self):
        """Check and update expired trial tenants"""
        current_time = time.time()

        for tenant in self.tenants.values():
            if (
                tenant.status == TenantStatus.TRIAL
                and tenant.trial_expires_at
                and current_time > tenant.trial_expires_at
            ):
                tenant.status = TenantStatus.SUSPENDED
                tenant.suspended_reason = "Trial period expired"
                logger.info(f"Trial expired for tenant: {tenant.tenant_id}")

    def migrate_tenant(
        self,
        tenant_id: str,
        new_isolation_level: IsolationLevel,
    ) -> bool:
        """Migrate tenant to a different isolation level"""
        tenant = self.tenants.get(tenant_id)
        if not tenant:
            return False

        old_level = tenant.isolation_level
        tenant.isolation_level = new_isolation_level

        # Update database/schema names
        if new_isolation_level == IsolationLevel.SCHEMA:
            tenant.schema_name = f"tenant_{tenant.subdomain}"
            tenant.database_name = None
        elif new_isolation_level == IsolationLevel.DATABASE:
            tenant.database_name = f"ghidra_tenant_{tenant.subdomain}"
            tenant.schema_name = None
        else:
            tenant.schema_name = None
            tenant.database_name = None

        logger.info(
            f"Tenant migrated: {tenant_id} - {old_level.value} -> {new_isolation_level.value}"
        )

        return True

    def export_tenant_data(self, tenant_id: str) -> Dict[str, Any]:
        """Export all tenant data (for compliance/migration)"""
        tenant = self.tenants.get(tenant_id)
        if not tenant:
            return {}

        data = {
            "tenant_info": {
                "tenant_id": tenant.tenant_id,
                "tenant_name": tenant.tenant_name,
                "subdomain": tenant.subdomain,
                "status": tenant.status.value,
                "tier": tenant.tier.value,
                "created_at": tenant.created_at,
            },
            "users": [
                {
                    "user_id": user.user_id,
                    "username": user.username,
                    "email": user.email,
                    "roles": user.roles,
                }
                for user in self.tenant_users.get(tenant_id, [])
            ],
            "usage": {
                "analyses": tenant.usage.analyses_count,
                "storage_bytes": tenant.usage.storage_bytes,
                "api_calls": tenant.usage.api_calls_count,
            },
            "config": {
                "isolation_level": tenant.isolation_level.value,
                "data_residency_region": tenant.config.data_residency_region,
            },
        }

        logger.info(f"Tenant data exported: {tenant_id}")

        return data

    def get_multi_tenant_stats(self) -> Dict[str, Any]:
        """Get overall multi-tenancy statistics"""
        total_tenants = len(self.tenants)
        active_tenants = sum(
            1 for t in self.tenants.values() if t.status == TenantStatus.ACTIVE
        )
        trial_tenants = sum(
            1 for t in self.tenants.values() if t.status == TenantStatus.TRIAL
        )

        tier_distribution = {}
        for tier in TenantTier:
            tier_distribution[tier.value] = sum(
                1 for t in self.tenants.values() if t.tier == tier
            )

        return {
            "total_tenants": total_tenants,
            "active_tenants": active_tenants,
            "trial_tenants": trial_tenants,
            "suspended_tenants": sum(
                1 for t in self.tenants.values() if t.status == TenantStatus.SUSPENDED
            ),
            "tier_distribution": tier_distribution,
            "total_users": sum(len(users) for users in self.tenant_users.values()),
        }


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Create multi-tenancy manager
    manager = MultiTenancyManager()

    # Create tenants
    tenant1 = manager.create_tenant(
        tenant_name="Acme Corporation",
        subdomain="acme",
        admin_email="admin@acme.com",
        admin_name="John Doe",
        tier=TenantTier.PROFESSIONAL,
        isolation_level=IsolationLevel.SCHEMA,
    )

    tenant2 = manager.create_tenant(
        tenant_name="TechStart Inc",
        subdomain="techstart",
        admin_email="admin@techstart.com",
        admin_name="Jane Smith",
        tier=TenantTier.FREE,
        trial_days=30,
    )

    print(f"Created tenants:")
    print(f"  - {tenant1.tenant_name}: {tenant1.tenant_id}")
    print(f"  - {tenant2.tenant_name}: {tenant2.tenant_id}")

    # Add users to tenant
    user = manager.add_tenant_user(
        tenant1.tenant_id,
        username="alice",
        email="alice@acme.com",
        roles=["analyst"],
    )

    # Check quota
    allowed, error = manager.check_quota(tenant1.tenant_id, ResourceType.ANALYSES)
    print(f"\nQuota check: {allowed}, Error: {error}")

    # Consume quota
    manager.consume_quota(tenant1.tenant_id, ResourceType.ANALYSES, 10)

    # Get usage report
    report = manager.get_usage_report(tenant1.tenant_id)
    print(f"\nUsage report: {json.dumps(report, indent=2)}")

    # Get stats
    stats = manager.get_multi_tenant_stats()
    print(f"\nMulti-tenancy stats: {json.dumps(stats, indent=2)}")

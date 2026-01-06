"""
GDPR Compliance Module for GhidraInsight

This module provides comprehensive GDPR (General Data Protection Regulation) compliance
features including data subject rights, consent management, data retention, privacy
impact assessments, and breach notification.

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


class DataSubjectRight(Enum):
    """GDPR Data Subject Rights (Articles 15-22)"""

    ACCESS = "access"  # Article 15: Right of access
    RECTIFICATION = "rectification"  # Article 16: Right to rectification
    ERASURE = "erasure"  # Article 17: Right to erasure (right to be forgotten)
    RESTRICTION = "restriction"  # Article 18: Right to restriction of processing
    PORTABILITY = "portability"  # Article 20: Right to data portability
    OBJECTION = "objection"  # Article 21: Right to object
    AUTOMATED_DECISION = "automated_decision"  # Article 22: Automated decisions


class ConsentPurpose(Enum):
    """Purposes for data processing requiring consent"""

    ANALYSIS = "analysis"
    MARKETING = "marketing"
    ANALYTICS = "analytics"
    PROFILING = "profiling"
    THIRD_PARTY_SHARING = "third_party_sharing"
    AUTOMATED_DECISION_MAKING = "automated_decision_making"


class LegalBasis(Enum):
    """Legal basis for processing personal data (Article 6)"""

    CONSENT = "consent"
    CONTRACT = "contract"
    LEGAL_OBLIGATION = "legal_obligation"
    VITAL_INTERESTS = "vital_interests"
    PUBLIC_TASK = "public_task"
    LEGITIMATE_INTERESTS = "legitimate_interests"


class DataCategory(Enum):
    """Categories of personal data"""

    BASIC_IDENTITY = "basic_identity"  # Name, email, etc.
    CONTACT = "contact"  # Address, phone
    FINANCIAL = "financial"
    TECHNICAL = "technical"  # IP address, device info
    USAGE = "usage"  # Activity logs, analysis history
    LOCATION = "location"
    BIOMETRIC = "biometric"
    SPECIAL_CATEGORY = "special_category"  # Sensitive data under Article 9


class BreachSeverity(Enum):
    """Data breach severity levels"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Consent:
    """Consent record for data processing"""

    consent_id: str
    data_subject_id: str
    purpose: ConsentPurpose
    granted: bool
    granted_at: Optional[float] = None
    withdrawn_at: Optional[float] = None
    consent_text: str = ""
    version: str = "1.0"
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DataSubjectRequest:
    """Request from data subject exercising their rights"""

    request_id: str
    data_subject_id: str
    request_type: DataSubjectRight
    submitted_at: float
    status: str = "pending"  # pending, processing, completed, rejected
    completed_at: Optional[float] = None
    response_data: Optional[Dict[str, Any]] = None
    notes: str = ""
    verification_method: str = ""
    verified: bool = False


@dataclass
class DataRetentionPolicy:
    """Data retention policy configuration"""

    policy_id: str
    data_category: DataCategory
    retention_period_days: int
    legal_basis: LegalBasis
    description: str
    auto_delete: bool = True
    created_at: float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)


@dataclass
class ProcessingActivity:
    """Record of processing activity (Article 30)"""

    activity_id: str
    name: str
    purpose: str
    data_categories: List[DataCategory]
    data_subjects: List[str]  # Categories like "customers", "employees"
    recipients: List[str]  # Who receives the data
    legal_basis: LegalBasis
    retention_period: str
    technical_measures: List[str]
    organizational_measures: List[str]
    cross_border_transfers: List[str]  # Countries
    data_processor: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    last_reviewed: float = field(default_factory=time.time)


@dataclass
class DataBreach:
    """Data breach incident record"""

    breach_id: str
    discovered_at: float
    occurred_at: float
    severity: BreachSeverity
    data_categories_affected: List[DataCategory]
    number_of_subjects: int
    description: str
    containment_measures: List[str] = field(default_factory=list)
    notification_required: bool = True
    authority_notified_at: Optional[float] = None
    subjects_notified_at: Optional[float] = None
    resolution_status: str = "investigating"
    impact_assessment: Optional[str] = None
    lessons_learned: Optional[str] = None


@dataclass
class PrivacyImpactAssessment:
    """Privacy Impact Assessment (DPIA) for high-risk processing"""

    pia_id: str
    processing_activity_id: str
    conducted_at: float
    conducted_by: str
    necessity_assessment: str
    proportionality_assessment: str
    risks_identified: List[Dict[str, Any]]
    safeguards: List[str]
    consultation_required: bool
    dpo_consulted: bool = False
    authority_consulted: bool = False
    approval_status: str = "pending"
    next_review_date: Optional[float] = None


@dataclass
class DataTransfer:
    """Cross-border data transfer record"""

    transfer_id: str
    data_subject_id: str
    source_country: str
    destination_country: str
    legal_mechanism: str  # "adequacy_decision", "scc", "bcr", "consent"
    purpose: str
    data_categories: List[DataCategory]
    timestamp: float = field(default_factory=time.time)
    recipient: str = ""
    safeguards: List[str] = field(default_factory=list)


@dataclass
class AnonymizationRecord:
    """Record of data anonymization/pseudonymization"""

    record_id: str
    original_data_id: str
    anonymization_method: str  # "k_anonymity", "l_diversity", "differential_privacy"
    anonymized_at: float
    reversible: bool
    key_stored: bool = False
    verification_passed: bool = False


class GDPRComplianceManager:
    """
    GDPR Compliance Manager for GhidraInsight.

    Implements GDPR requirements including data subject rights, consent management,
    data retention, breach notification, and compliance reporting.
    """

    def __init__(self):
        self.consents: Dict[str, List[Consent]] = {}  # data_subject_id -> consents
        self.requests: Dict[str, DataSubjectRequest] = {}  # request_id -> request
        self.retention_policies: Dict[DataCategory, DataRetentionPolicy] = {}
        self.processing_activities: Dict[str, ProcessingActivity] = {}
        self.data_breaches: Dict[str, DataBreach] = {}
        self.privacy_assessments: Dict[str, PrivacyImpactAssessment] = {}
        self.data_transfers: List[DataTransfer] = []
        self.anonymization_records: Dict[str, AnonymizationRecord] = {}

        # Compliance configuration
        self.dpo_email = "dpo@ghidrainsight.com"
        self.supervisory_authority = "ICO"  # Example: UK's ICO
        self.breach_notification_deadline = 72 * 3600  # 72 hours in seconds

        # Initialize default retention policies
        self._initialize_default_policies()

    def _initialize_default_policies(self):
        """Initialize default data retention policies"""
        default_policies = [
            DataRetentionPolicy(
                policy_id="policy_basic_identity",
                data_category=DataCategory.BASIC_IDENTITY,
                retention_period_days=365 * 7,  # 7 years
                legal_basis=LegalBasis.CONTRACT,
                description="User account information",
            ),
            DataRetentionPolicy(
                policy_id="policy_usage",
                data_category=DataCategory.USAGE,
                retention_period_days=365 * 2,  # 2 years
                legal_basis=LegalBasis.LEGITIMATE_INTERESTS,
                description="Usage logs and analysis history",
            ),
            DataRetentionPolicy(
                policy_id="policy_technical",
                data_category=DataCategory.TECHNICAL,
                retention_period_days=90,
                legal_basis=LegalBasis.LEGITIMATE_INTERESTS,
                description="Technical logs (IP addresses, etc.)",
            ),
        ]

        for policy in default_policies:
            self.retention_policies[policy.data_category] = policy

    # Consent Management

    def record_consent(
        self,
        data_subject_id: str,
        purpose: ConsentPurpose,
        granted: bool,
        consent_text: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Consent:
        """Record consent from data subject"""
        consent_id = f"consent_{secrets.token_hex(12)}"

        consent = Consent(
            consent_id=consent_id,
            data_subject_id=data_subject_id,
            purpose=purpose,
            granted=granted,
            granted_at=time.time() if granted else None,
            consent_text=consent_text,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        if data_subject_id not in self.consents:
            self.consents[data_subject_id] = []

        self.consents[data_subject_id].append(consent)

        logger.info(
            f"Consent recorded: {data_subject_id} - {purpose.value} - "
            f"{'granted' if granted else 'denied'}"
        )

        return consent

    def withdraw_consent(self, data_subject_id: str, purpose: ConsentPurpose) -> bool:
        """Withdraw consent for a specific purpose"""
        if data_subject_id not in self.consents:
            return False

        for consent in self.consents[data_subject_id]:
            if consent.purpose == purpose and consent.granted:
                consent.granted = False
                consent.withdrawn_at = time.time()
                logger.info(f"Consent withdrawn: {data_subject_id} - {purpose.value}")
                return True

        return False

    def check_consent(self, data_subject_id: str, purpose: ConsentPurpose) -> bool:
        """Check if valid consent exists for a purpose"""
        if data_subject_id not in self.consents:
            return False

        for consent in self.consents[data_subject_id]:
            if (
                consent.purpose == purpose
                and consent.granted
                and consent.withdrawn_at is None
            ):
                return True

        return False

    # Data Subject Rights

    def submit_access_request(
        self, data_subject_id: str, verification_method: str
    ) -> DataSubjectRequest:
        """Submit right of access request (Article 15)"""
        return self._create_request(
            data_subject_id,
            DataSubjectRight.ACCESS,
            verification_method,
        )

    def submit_erasure_request(
        self, data_subject_id: str, verification_method: str
    ) -> DataSubjectRequest:
        """Submit right to erasure request (Article 17)"""
        return self._create_request(
            data_subject_id,
            DataSubjectRight.ERASURE,
            verification_method,
        )

    def submit_portability_request(
        self, data_subject_id: str, verification_method: str
    ) -> DataSubjectRequest:
        """Submit right to data portability request (Article 20)"""
        return self._create_request(
            data_subject_id,
            DataSubjectRight.PORTABILITY,
            verification_method,
        )

    def _create_request(
        self,
        data_subject_id: str,
        request_type: DataSubjectRight,
        verification_method: str,
    ) -> DataSubjectRequest:
        """Create a data subject request"""
        request_id = f"dsr_{secrets.token_hex(12)}"

        request = DataSubjectRequest(
            request_id=request_id,
            data_subject_id=data_subject_id,
            request_type=request_type,
            submitted_at=time.time(),
            verification_method=verification_method,
        )

        self.requests[request_id] = request

        logger.info(
            f"Data subject request submitted: {request_type.value} - {request_id}"
        )

        return request

    def verify_request(self, request_id: str) -> bool:
        """Verify the identity of the requester"""
        request = self.requests.get(request_id)
        if not request:
            return False

        # In production, implement actual verification logic
        # (e.g., email verification, ID check, etc.)
        request.verified = True
        logger.info(f"Request verified: {request_id}")

        return True

    def process_access_request(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Process right of access request and return personal data"""
        request = self.requests.get(request_id)
        if not request or not request.verified:
            return None

        if request.request_type != DataSubjectRight.ACCESS:
            return None

        request.status = "processing"

        # Gather all personal data for the subject
        data_subject_id = request.data_subject_id

        personal_data = {
            "data_subject_id": data_subject_id,
            "exported_at": datetime.now().isoformat(),
            "consents": [
                {
                    "purpose": c.purpose.value,
                    "granted": c.granted,
                    "granted_at": datetime.fromtimestamp(c.granted_at).isoformat()
                    if c.granted_at
                    else None,
                }
                for c in self.consents.get(data_subject_id, [])
            ],
            "data_transfers": [
                {
                    "destination_country": t.destination_country,
                    "purpose": t.purpose,
                    "timestamp": datetime.fromtimestamp(t.timestamp).isoformat(),
                }
                for t in self.data_transfers
                if t.data_subject_id == data_subject_id
            ],
            "processing_activities": [
                {
                    "name": a.name,
                    "purpose": a.purpose,
                    "legal_basis": a.legal_basis.value,
                }
                for a in self.processing_activities.values()
            ],
        }

        request.status = "completed"
        request.completed_at = time.time()
        request.response_data = personal_data

        logger.info(f"Access request processed: {request_id}")

        return personal_data

    def process_erasure_request(self, request_id: str) -> bool:
        """Process right to erasure request (right to be forgotten)"""
        request = self.requests.get(request_id)
        if not request or not request.verified:
            return False

        if request.request_type != DataSubjectRight.ERASURE:
            return False

        request.status = "processing"
        data_subject_id = request.data_subject_id

        # Check if erasure is possible (legal obligations, etc.)
        if not self._can_erase_data(data_subject_id):
            request.status = "rejected"
            request.notes = "Cannot erase data due to legal obligations"
            logger.warning(f"Erasure request rejected: {request_id}")
            return False

        # Perform erasure
        self._erase_personal_data(data_subject_id)

        request.status = "completed"
        request.completed_at = time.time()

        logger.info(f"Erasure request processed: {request_id}")

        return True

    def _can_erase_data(self, data_subject_id: str) -> bool:
        """Check if data can be erased (considering legal obligations)"""
        # In production, check for:
        # - Active contracts
        # - Legal retention requirements
        # - Pending legal proceedings
        # - Tax/accounting obligations
        return True

    def _erase_personal_data(self, data_subject_id: str):
        """Erase all personal data for a data subject"""
        # Remove consents
        if data_subject_id in self.consents:
            del self.consents[data_subject_id]

        # Remove data transfers
        self.data_transfers = [
            t for t in self.data_transfers if t.data_subject_id != data_subject_id
        ]

        # In production, this would also:
        # - Delete from databases
        # - Remove from backups
        # - Clear from caches
        # - Notify data processors

        logger.info(f"Personal data erased: {data_subject_id}")

    def export_personal_data(
        self, data_subject_id: str, format: str = "json"
    ) -> Dict[str, Any]:
        """Export personal data in machine-readable format (portability)"""
        # Similar to access request but in structured format
        return self.process_access_request(
            self._create_request(
                data_subject_id,
                DataSubjectRight.PORTABILITY,
                "automated",
            ).request_id
        )

    # Data Retention

    def add_retention_policy(self, policy: DataRetentionPolicy):
        """Add a data retention policy"""
        self.retention_policies[policy.data_category] = policy
        logger.info(
            f"Retention policy added: {policy.data_category.value} - "
            f"{policy.retention_period_days} days"
        )

    def enforce_retention_policies(self) -> Dict[str, int]:
        """Enforce data retention policies (delete old data)"""
        current_time = time.time()
        deleted_counts = {}

        for category, policy in self.retention_policies.items():
            if not policy.auto_delete:
                continue

            cutoff_time = current_time - (policy.retention_period_days * 86400)

            # In production, this would query database and delete old records
            deleted_count = 0  # Placeholder

            deleted_counts[category.value] = deleted_count

            if deleted_count > 0:
                logger.info(
                    f"Retention policy enforced: {category.value} - "
                    f"{deleted_count} records deleted"
                )

        return deleted_counts

    # Processing Activities (Article 30)

    def register_processing_activity(self, activity: ProcessingActivity) -> str:
        """Register a processing activity"""
        self.processing_activities[activity.activity_id] = activity
        logger.info(f"Processing activity registered: {activity.name}")
        return activity.activity_id

    def get_processing_record(self) -> List[Dict[str, Any]]:
        """Get record of processing activities (ROPA)"""
        return [
            {
                "name": a.name,
                "purpose": a.purpose,
                "data_categories": [c.value for c in a.data_categories],
                "legal_basis": a.legal_basis.value,
                "retention_period": a.retention_period,
                "cross_border_transfers": a.cross_border_transfers,
            }
            for a in self.processing_activities.values()
        ]

    # Data Breach Management

    def report_data_breach(
        self,
        occurred_at: float,
        severity: BreachSeverity,
        data_categories: List[DataCategory],
        number_of_subjects: int,
        description: str,
    ) -> DataBreach:
        """Report a data breach"""
        breach_id = f"breach_{secrets.token_hex(12)}"

        breach = DataBreach(
            breach_id=breach_id,
            discovered_at=time.time(),
            occurred_at=occurred_at,
            severity=severity,
            data_categories_affected=data_categories,
            number_of_subjects=number_of_subjects,
            description=description,
        )

        self.data_breaches[breach_id] = breach

        # Check if notification is required (within 72 hours)
        time_since_discovery = time.time() - breach.discovered_at
        if breach.notification_required:
            logger.critical(
                f"Data breach reported: {breach_id} - Severity: {severity.value} - "
                f"Notification deadline: {72 - (time_since_discovery / 3600):.1f} hours"
            )

        return breach

    def notify_breach_to_authority(self, breach_id: str) -> bool:
        """Notify data breach to supervisory authority"""
        breach = self.data_breaches.get(breach_id)
        if not breach:
            return False

        # In production, send actual notification
        breach.authority_notified_at = time.time()

        logger.info(
            f"Breach notification sent to authority: {breach_id} - "
            f"{self.supervisory_authority}"
        )

        return True

    def notify_breach_to_subjects(self, breach_id: str) -> bool:
        """Notify affected data subjects of breach"""
        breach = self.data_breaches.get(breach_id)
        if not breach:
            return False

        # High-risk breaches require subject notification
        if breach.severity in [BreachSeverity.HIGH, BreachSeverity.CRITICAL]:
            # In production, send notifications to affected subjects
            breach.subjects_notified_at = time.time()

            logger.info(
                f"Breach notification sent to {breach.number_of_subjects} subjects"
            )

        return True

    # Privacy Impact Assessments

    def conduct_pia(
        self,
        processing_activity_id: str,
        conducted_by: str,
        risks: List[Dict[str, Any]],
        safeguards: List[str],
    ) -> PrivacyImpactAssessment:
        """Conduct Privacy Impact Assessment (DPIA)"""
        pia_id = f"pia_{secrets.token_hex(12)}"

        pia = PrivacyImpactAssessment(
            pia_id=pia_id,
            processing_activity_id=processing_activity_id,
            conducted_at=time.time(),
            conducted_by=conducted_by,
            necessity_assessment="Assessment text here",
            proportionality_assessment="Assessment text here",
            risks_identified=risks,
            safeguards=safeguards,
            consultation_required=len(risks) > 0,
        )

        self.privacy_assessments[pia_id] = pia

        logger.info(f"Privacy Impact Assessment conducted: {pia_id}")

        return pia

    # Cross-border Data Transfers

    def record_data_transfer(
        self,
        data_subject_id: str,
        destination_country: str,
        purpose: str,
        legal_mechanism: str,
        data_categories: List[DataCategory],
    ) -> DataTransfer:
        """Record cross-border data transfer"""
        transfer_id = f"transfer_{secrets.token_hex(12)}"

        # Validate transfer mechanism
        if not self._validate_transfer_mechanism(destination_country, legal_mechanism):
            raise ValueError(f"Invalid transfer mechanism for {destination_country}")

        transfer = DataTransfer(
            transfer_id=transfer_id,
            data_subject_id=data_subject_id,
            source_country="EU",  # Example
            destination_country=destination_country,
            legal_mechanism=legal_mechanism,
            purpose=purpose,
            data_categories=data_categories,
        )

        self.data_transfers.append(transfer)

        logger.info(
            f"Data transfer recorded: {destination_country} - {legal_mechanism}"
        )

        return transfer

    def _validate_transfer_mechanism(
        self, destination_country: str, mechanism: str
    ) -> bool:
        """Validate that the transfer mechanism is appropriate"""
        # Adequacy decisions (countries with adequate protection)
        adequate_countries = [
            "CH",
            "CA",
            "IL",
            "NZ",
            "AR",
            "JP",
            "UK",
        ]  # Simplified list

        if destination_country in adequate_countries:
            return mechanism == "adequacy_decision"

        # Other countries require SCC, BCR, or consent
        return mechanism in ["scc", "bcr", "consent"]

    # Data Anonymization

    def anonymize_data(
        self,
        original_data_id: str,
        method: str,
        reversible: bool = False,
    ) -> AnonymizationRecord:
        """Anonymize personal data"""
        record_id = f"anon_{secrets.token_hex(12)}"

        record = AnonymizationRecord(
            record_id=record_id,
            original_data_id=original_data_id,
            anonymization_method=method,
            anonymized_at=time.time(),
            reversible=reversible,
        )

        self.anonymization_records[record_id] = record

        logger.info(f"Data anonymized: {original_data_id} - Method: {method}")

        return record

    # Compliance Reporting

    def generate_compliance_report(self) -> Dict[str, Any]:
        """Generate comprehensive GDPR compliance report"""
        report = {
            "report_generated_at": datetime.now().isoformat(),
            "dpo_contact": self.dpo_email,
            "summary": {
                "total_data_subjects": len(self.consents),
                "active_consents": sum(
                    len([c for c in consents if c.granted])
                    for consents in self.consents.values()
                ),
                "data_subject_requests": {
                    "total": len(self.requests),
                    "pending": len(
                        [r for r in self.requests.values() if r.status == "pending"]
                    ),
                    "completed": len(
                        [r for r in self.requests.values() if r.status == "completed"]
                    ),
                },
                "data_breaches": {
                    "total": len(self.data_breaches),
                    "last_30_days": len(
                        [
                            b
                            for b in self.data_breaches.values()
                            if b.discovered_at > time.time() - (30 * 86400)
                        ]
                    ),
                },
                "cross_border_transfers": len(self.data_transfers),
            },
            "processing_activities": len(self.processing_activities),
            "privacy_assessments": len(self.privacy_assessments),
            "retention_policies": len(self.retention_policies),
            "compliance_status": self._assess_compliance_status(),
        }

        return report

    def _assess_compliance_status(self) -> Dict[str, Any]:
        """Assess overall compliance status"""
        issues = []

        # Check for unprocessed requests
        pending_requests = [r for r in self.requests.values() if r.status == "pending"]
        if pending_requests:
            issues.append(f"{len(pending_requests)} pending data subject requests")

        # Check for unreported breaches
        unreported_breaches = [
            b
            for b in self.data_breaches.values()
            if b.authority_notified_at is None and b.notification_required
        ]
        if unreported_breaches:
            issues.append(f"{len(unreported_breaches)} unreported data breaches")

        # Check for expired PIAs
        expired_pias = [
            p
            for p in self.privacy_assessments.values()
            if p.next_review_date and p.next_review_date < time.time()
        ]
        if expired_pias:
            issues.append(f"{len(expired_pias)} expired privacy assessments")

        return {
            "compliant": len(issues) == 0,
            "issues": issues,
            "last_assessment": datetime.now().isoformat(),
        }

    def export_compliance_data(self, output_path: str, format: str = "json"):
        """Export all compliance data for audit"""
        data = {
            "consents": {
                subject_id: [
                    {
                        "consent_id": c.consent_id,
                        "purpose": c.purpose.value,
                        "granted": c.granted,
                        "granted_at": c.granted_at,
                    }
                    for c in consents
                ]
                for subject_id, consents in self.consents.items()
            },
            "data_subject_requests": [
                {
                    "request_id": r.request_id,
                    "request_type": r.request_type.value,
                    "status": r.status,
                    "submitted_at": r.submitted_at,
                }
                for r in self.requests.values()
            ],
            "data_breaches": [
                {
                    "breach_id": b.breach_id,
                    "severity": b.severity.value,
                    "discovered_at": b.discovered_at,
                }
                for b in self.data_breaches.values()
            ],
            "processing_activities": self.get_processing_record(),
        }

        if format == "json":
            with open(output_path, "w") as f:
                json.dump(data, f, indent=2)

        logger.info(f"Compliance data exported to {output_path}")


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Create compliance manager
    gdpr = GDPRComplianceManager()

    # Record consent
    consent = gdpr.record_consent(
        data_subject_id="user_123",
        purpose=ConsentPurpose.ANALYSIS,
        granted=True,
        consent_text="I consent to analysis of my uploaded binaries",
        ip_address="192.168.1.1",
    )

    # Submit access request
    request = gdpr.submit_access_request(
        data_subject_id="user_123",
        verification_method="email",
    )

    # Verify and process request
    gdpr.verify_request(request.request_id)
    data = gdpr.process_access_request(request.request_id)
    print(f"Access request processed: {json.dumps(data, indent=2)}")

    # Report data breach
    breach = gdpr.report_data_breach(
        occurred_at=time.time() - 3600,
        severity=BreachSeverity.HIGH,
        data_categories=[DataCategory.BASIC_IDENTITY, DataCategory.TECHNICAL],
        number_of_subjects=100,
        description="Unauthorized access to user database",
    )

    # Generate compliance report
    report = gdpr.generate_compliance_report()
    print(f"\nCompliance Report: {json.dumps(report, indent=2)}")

    # Export compliance data
    gdpr.export_compliance_data("gdpr_compliance_data.json")

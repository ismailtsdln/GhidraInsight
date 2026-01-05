"""Repository classes for database operations."""

from datetime import datetime
from typing import List, Optional
from sqlalchemy.orm import Session

from .models import BinaryAnalysis, Function, Vulnerability, AnalysisCache


class BinaryAnalysisRepository:
    """Repository for binary analysis operations."""

    def __init__(self, db: Session):
        self.db = db

    def create(self, binary_name: str, binary_hash: str, file_size: int,
               architecture: Optional[str] = None, endianness: Optional[str] = None) -> BinaryAnalysis:
        """Create a new binary analysis record."""
        analysis = BinaryAnalysis(
            binary_name=binary_name,
            binary_hash=binary_hash,
            file_size=file_size,
            architecture=architecture,
            endianness=endianness
        )
        self.db.add(analysis)
        self.db.commit()
        self.db.refresh(analysis)
        return analysis

    def get_by_hash(self, binary_hash: str) -> Optional[BinaryAnalysis]:
        """Get analysis by binary hash."""
        return self.db.query(BinaryAnalysis).filter(BinaryAnalysis.binary_hash == binary_hash).first()

    def get_all(self) -> List[BinaryAnalysis]:
        """Get all analyses."""
        return self.db.query(BinaryAnalysis).all()


class FunctionRepository:
    """Repository for function operations."""

    def __init__(self, db: Session):
        self.db = db

    def create(self, analysis_id: int, name: Optional[str], address: str,
               size: Optional[int] = None, complexity: Optional[int] = None,
               decompiled_code: Optional[str] = None, signature: Optional[str] = None,
               is_entry_point: bool = False) -> Function:
        """Create a new function record."""
        function = Function(
            analysis_id=analysis_id,
            name=name,
            address=address,
            size=size,
            complexity=complexity,
            decompiled_code=decompiled_code,
            signature=signature,
            is_entry_point=is_entry_point
        )
        self.db.add(function)
        self.db.commit()
        self.db.refresh(function)
        return function

    def get_by_analysis(self, analysis_id: int) -> List[Function]:
        """Get all functions for an analysis."""
        return self.db.query(Function).filter(Function.analysis_id == analysis_id).all()


class VulnerabilityRepository:
    """Repository for vulnerability operations."""

    def __init__(self, db: Session):
        self.db = db

    def create(self, analysis_id: int, vuln_type: str, severity: str,
               cvss_score: Optional[int] = None, description: Optional[str] = None,
               location: Optional[str] = None, confidence: Optional[int] = None,
               metadata: Optional[dict] = None) -> Vulnerability:
        """Create a new vulnerability record."""
        vulnerability = Vulnerability(
            analysis_id=analysis_id,
            type=vuln_type,
            severity=severity,
            cvss_score=cvss_score,
            description=description,
            location=location,
            confidence=confidence,
            metadata=metadata
        )
        self.db.add(vulnerability)
        self.db.commit()
        self.db.refresh(vulnerability)
        return vulnerability

    def get_by_analysis(self, analysis_id: int) -> List[Vulnerability]:
        """Get all vulnerabilities for an analysis."""
        return self.db.query(Vulnerability).filter(Vulnerability.analysis_id == analysis_id).all()


class CacheRepository:
    """Repository for cache operations."""

    def __init__(self, db: Session):
        self.db = db

    def get(self, cache_key: str) -> Optional[dict]:
        """Get cached data by key."""
        cache_entry = self.db.query(AnalysisCache).filter(AnalysisCache.cache_key == cache_key).first()
        if cache_entry:
            return cache_entry.data
        return None

    def set(self, cache_key: str, data: dict, expires_at: Optional[datetime] = None):
        """Set cached data."""
        cache_entry = self.db.query(AnalysisCache).filter(AnalysisCache.cache_key == cache_key).first()
        if cache_entry:
            cache_entry.data = data
            cache_entry.expires_at = expires_at
        else:
            cache_entry = AnalysisCache(cache_key=cache_key, data=data, expires_at=expires_at)
            self.db.add(cache_entry)
        self.db.commit()

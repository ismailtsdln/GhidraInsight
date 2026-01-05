"""Database models for GhidraInsight."""

from datetime import datetime
from typing import Optional

from sqlalchemy import Column, DateTime, Integer, String, Text, JSON, ForeignKey, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class BinaryAnalysis(Base):
    """Model for storing binary analysis results."""
    __tablename__ = "binary_analyses"

    id = Column(Integer, primary_key=True, index=True)
    binary_name = Column(String(255), nullable=False)
    binary_hash = Column(String(64), nullable=False, unique=True, index=True)
    file_size = Column(Integer, nullable=False)
    architecture = Column(String(50))
    endianness = Column(String(10))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    functions = relationship("Function", back_populates="analysis", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="analysis", cascade="all, delete-orphan")


class Function(Base):
    """Model for storing function analysis results."""
    __tablename__ = "functions"

    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("binary_analyses.id"), nullable=False)
    name = Column(String(255))
    address = Column(String(20), nullable=False, index=True)
    size = Column(Integer)
    complexity = Column(Integer)
    decompiled_code = Column(Text)
    signature = Column(String(500))
    is_entry_point = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    analysis = relationship("BinaryAnalysis", back_populates="functions")


class Vulnerability(Base):
    """Model for storing vulnerability findings."""
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("binary_analyses.id"), nullable=False)
    type = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    cvss_score = Column(Integer)  # 0-10
    description = Column(Text)
    location = Column(String(20))  # Address or function name
    confidence = Column(Integer)  # 0-100
    metadata = Column(JSON)  # Additional data
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    analysis = relationship("BinaryAnalysis", back_populates="vulnerabilities")


class AnalysisCache(Base):
    """Model for caching analysis results."""
    __tablename__ = "analysis_cache"

    id = Column(Integer, primary_key=True, index=True)
    cache_key = Column(String(255), nullable=False, unique=True, index=True)
    data = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)

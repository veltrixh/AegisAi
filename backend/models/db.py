import os
import json
from datetime import datetime
from typing import Optional, List, Dict, Any
from sqlalchemy import (
    create_engine, Column, String, Integer, Float, Text, Boolean, DateTime, ForeignKey
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///vuln_scanner.db")

Base = declarative_base()

class DBScan(Base):
    __tablename__ = "scans"

    id = Column(String(64), primary_key=True)
    target_url = Column(String(512), nullable=False)
    profile = Column(String(64), default="standard")
    status = Column(String(32), default="pending")
    progress = Column(Integer, default=0)
    current_phase = Column(String(128), default="Initialized")
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, default=0.0)
    config_json = Column(Text, default="{}")
    summary_json = Column(Text, default="{}")
    attack_graph_json = Column(Text, default="{}")
    correlations_json = Column(Text, default="[]")
    error_message = Column(Text, nullable=True)

    findings = relationship("DBFinding", back_populates="scan", cascade="all, delete-orphan")

class DBFinding(Base):
    __tablename__ = "findings"

    id = Column(String(64), primary_key=True)
    scan_id = Column(String(64), ForeignKey("scans.id"), nullable=False)
    type = Column(String(64), nullable=False)
    title = Column(String(256), nullable=False)
    target = Column(String(512), nullable=False)
    parameter = Column(String(128), nullable=True)
    method = Column(String(16), default="GET")
    severity = Column(String(32), default="MEDIUM")
    risk_score = Column(Float, default=5.0)
    cvss = Column(Float, default=5.0)
    cvss_vector = Column(String(128), default="")
    confidence = Column(Float, default=80.0)
    validation_status = Column(String(32), default="Likely")
    owasp_json = Column(Text, default="{}")
    cwe_json = Column(Text, default="{}")
    evidence_json = Column(Text, default="{}")
    ai_explanation_json = Column(Text, nullable=True)
    remediation_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("DBScan", back_populates="findings")

class DBReport(Base):
    __tablename__ = "reports"

    id = Column(String(64), primary_key=True)
    scan_id = Column(String(64), ForeignKey("scans.id"), nullable=False)
    format = Column(String(32), nullable=False)  # json, sarif, html, pdf
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
    echo=False
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

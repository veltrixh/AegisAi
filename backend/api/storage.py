import json
from datetime import datetime
from typing import Any, Dict, Optional, List
from backend.models.scan import ScanModel
from backend.models.finding import FindingModel
from backend.models.db import SessionLocal, DBScan, DBFinding, init_db
from backend.utils.logger import logger

class ScanStore:
    """Manages active scan instances and coordinates persistence."""
    _active_scans: Dict[str, ScanModel] = {}
    _active_orchestrators: Dict[str, Any] = {}

    @classmethod
    def register_orchestrator(cls, scan_id: str, orchestrator):
        cls._active_orchestrators[scan_id] = orchestrator

    @classmethod
    def get_orchestrator(cls, scan_id: str):
        return cls._active_orchestrators.get(scan_id)

    @classmethod
    def save(cls, scan: ScanModel):
        cls._active_scans[scan.id] = scan
        # Sync with database
        try:
            db = SessionLocal()
            try:
                db_scan = db.query(DBScan).filter(DBScan.id == scan.id).first()
                if not db_scan:
                    db_scan = DBScan(id=scan.id, target_url=scan.target_url)
                    db.add(db_scan)

                db_scan.profile = scan.profile
                db_scan.status = scan.status
                db_scan.progress = scan.progress
                db_scan.current_phase = scan.current_phase
                db_scan.completed_at = (
                    datetime.fromisoformat(scan.completed_at.replace("Z", "+00:00"))
                    if scan.completed_at else None
                )
                db_scan.duration_seconds = scan.duration_seconds
                db_scan.error_message = scan.error_message
                db_scan.config_json = scan.config.model_dump_json()
                db_scan.summary_json = scan.summary.model_dump_json()
                db_scan.attack_graph_json = scan.attack_graph.model_dump_json()
                db_scan.correlations_json = json.dumps([c.model_dump() for c in scan.correlations])

                # Save findings if completed
                if scan.status in ("completed", "running") and scan.findings:
                    existing_finding_ids = set(f.id for f in db.query(DBFinding.id).filter(DBFinding.scan_id == scan.id).all())
                    for f in scan.findings:
                        if f.finding_id not in existing_finding_ids:
                            db_finding = DBFinding(
                                id=f.finding_id,
                                scan_id=scan.id,
                                type=f.type,
                                title=f.title,
                                target=f.target,
                                parameter=f.parameter,
                                method=f.method,
                                severity=f.severity,
                                risk_score=f.risk_score,
                                cvss=f.cvss,
                                cvss_vector=f.cvss_vector,
                                confidence=f.confidence,
                                validation_status=f.validation_status,
                                owasp_json=json.dumps(f.owasp),
                                cwe_json=json.dumps(f.cwe),
                                evidence_json=f.evidence.model_dump_json(),
                                ai_explanation_json=json.dumps(f.ai_explanation) if f.ai_explanation else None,
                                remediation_json=json.dumps(f.remediation) if f.remediation else None
                            )
                            db.add(db_finding)
                db.commit()
            finally:
                db.close()
        except Exception as e:
            logger.debug(f"DB persistence sync: {e}")

    @classmethod
    def get(cls, scan_id: str) -> Optional[ScanModel]:
        if scan_id in cls._active_scans:
            return cls._active_scans[scan_id]
        # Query from DB
        try:
            db = SessionLocal()
            try:
                db_scan = db.query(DBScan).filter(DBScan.id == scan_id).first()
                if db_scan:
                    # Reconstruct ScanModel
                    from backend.models.scan import ScanConfig, ScanSummary, AttackGraphModel, VulnerabilityCorrelation
                    findings = []
                    for f in db_scan.findings:
                        from backend.models.evidence import EvidenceModel
                        findings.append(FindingModel(
                            finding_id=f.id,
                            scan_id=f.scan_id,
                            type=f.type,
                            title=f.title,
                            target=f.target,
                            parameter=f.parameter,
                            method=f.method,
                            severity=f.severity,
                            risk_score=f.risk_score,
                            cvss=f.cvss,
                            cvss_vector=f.cvss_vector,
                            confidence=f.confidence,
                            validation_status=f.validation_status,
                            owasp=json.loads(f.owasp_json or "{}"),
                            cwe=json.loads(f.cwe_json or "{}"),
                            evidence=EvidenceModel.model_validate_json(f.evidence_json),
                            ai_explanation=json.loads(f.ai_explanation_json) if f.ai_explanation_json else None,
                            remediation=json.loads(f.remediation_json) if f.remediation_json else None,
                            created_at=f.created_at.isoformat()
                        ))

                    scan_model = ScanModel(
                        id=db_scan.id,
                        target_url=db_scan.target_url,
                        profile=db_scan.profile,
                        status=db_scan.status,
                        progress=db_scan.progress,
                        current_phase=db_scan.current_phase,
                        created_at=db_scan.created_at.isoformat(),
                        completed_at=db_scan.completed_at.isoformat() if db_scan.completed_at else None,
                        duration_seconds=db_scan.duration_seconds,
                        config=ScanConfig.model_validate_json(db_scan.config_json or "{}"),
                        summary=ScanSummary.model_validate_json(db_scan.summary_json or "{}"),
                        findings=findings,
                        correlations=[VulnerabilityCorrelation(**c) for c in json.loads(db_scan.correlations_json or "[]")],
                        attack_graph=AttackGraphModel.model_validate_json(db_scan.attack_graph_json or "{}"),
                        error_message=db_scan.error_message
                    )
                    cls._active_scans[scan_id] = scan_model
                    return scan_model
            finally:
                db.close()
        except Exception as e:
            logger.debug(f"DB load error: {e}")
        return None

    @classmethod
    def list_all(cls) -> List[ScanModel]:
        # Merge DB scans and active scans
        scans: Dict[str, ScanModel] = dict(cls._active_scans)
        try:
            db = SessionLocal()
            try:
                db_scans = db.query(DBScan).order_by(DBScan.created_at.desc()).limit(50).all()
                for db_s in db_scans:
                    if db_s.id not in scans:
                        loaded = cls.get(db_s.id)
                        if loaded:
                            scans[db_s.id] = loaded
            finally:
                db.close()
        except Exception as e:
            logger.debug(f"DB list_all error: {e}")
        return sorted(list(scans.values()), key=lambda x: x.created_at, reverse=True)

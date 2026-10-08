from typing import Dict, Any, List, Set, Tuple
from backend.models.scan import ScanModel, ScanComparisonResult
from backend.models.finding import FindingModel

def _finding_fingerprint(f: FindingModel) -> str:
    """Computes a stable identity key for a finding across scans."""
    return f"{f.type.lower()}::{f.target.lower()}::{str(f.parameter).lower()}"

class ScanComparisonEngine:
    """
    Compares two scans (Baseline Scan A vs Current Scan B) to track
    vulnerability resolution, regressions, new discoveries, and posture delta.
    """

    @classmethod
    def compare(cls, scan_a: ScanModel, scan_b: ScanModel) -> ScanComparisonResult:
        a_map: Dict[str, FindingModel] = {_finding_fingerprint(f): f for f in scan_a.findings}
        b_map: Dict[str, FindingModel] = {_finding_fingerprint(f): f for f in scan_b.findings}

        new_findings: List[FindingModel] = []
        fixed_findings: List[FindingModel] = []
        unchanged_findings: List[FindingModel] = []
        regressed_findings: List[FindingModel] = []

        # Check findings in B against A
        for key, f_b in b_map.items():
            if key not in a_map:
                new_findings.append(f_b)
            else:
                f_a = a_map[key]
                if f_b.risk_score > f_a.risk_score:
                    regressed_findings.append(f_b)
                else:
                    unchanged_findings.append(f_b)

        # Check findings in A that are no longer in B
        for key, f_a in a_map.items():
            if key not in b_map:
                fixed_findings.append(f_a)

        score_before = scan_a.summary.security_score
        score_after = scan_b.summary.security_score
        improvement = round(score_after - score_before, 1)

        summary_counts = {
            "new": len(new_findings),
            "fixed": len(fixed_findings),
            "unchanged": len(unchanged_findings),
            "regressed": len(regressed_findings)
        }

        return ScanComparisonResult(
            base_scan_id=scan_a.id,
            target_scan_id=scan_b.id,
            new_findings=new_findings,
            fixed_findings=fixed_findings,
            unchanged_findings=unchanged_findings,
            regressed_findings=regressed_findings,
            score_before=score_before,
            score_after=score_after,
            score_improvement=improvement,
            summary=summary_counts
        )

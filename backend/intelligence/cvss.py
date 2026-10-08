import math
from typing import Dict, Any, Tuple

# CVSS v3.1 metric weight constants
AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC_WEIGHTS = {"L": 0.77, "H": 0.44}
PR_WEIGHTS = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},   # Scope Unchanged
    "C": {"N": 0.85, "L": 0.68, "H": 0.50}    # Scope Changed
}
UI_WEIGHTS = {"N": 0.85, "R": 0.62}
CIA_WEIGHTS = {"N": 0.0, "L": 0.22, "H": 0.56}

def round_up(val: float) -> float:
    """CVSS v3.1 Rounding (Round to next 0.1)."""
    return math.ceil(val * 10.0) / 10.0

def calculate_cvss_v3(
    av: str = "N",
    ac: str = "L",
    pr: str = "N",
    ui: str = "N",
    scope: str = "U",
    c: str = "H",
    i: str = "H",
    a: str = "H"
) -> Tuple[float, str]:
    """
    Computes deterministic CVSS v3.1 Base Score and vector string.
    Returns (score, vector_string).
    """
    scope = scope.upper()
    av_val = AV_WEIGHTS.get(av.upper(), 0.85)
    ac_val = AC_WEIGHTS.get(ac.upper(), 0.77)
    pr_val = PR_WEIGHTS.get(scope, PR_WEIGHTS["U"]).get(pr.upper(), 0.85)
    ui_val = UI_WEIGHTS.get(ui.upper(), 0.85)

    c_val = CIA_WEIGHTS.get(c.upper(), 0.56)
    i_val = CIA_WEIGHTS.get(i.upper(), 0.56)
    a_val = CIA_WEIGHTS.get(a.upper(), 0.56)

    iss = 1.0 - ((1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val))
    exploitability = 8.22 * av_val * ac_val * pr_val * ui_val

    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    if impact <= 0:
        base_score = 0.0
    elif scope == "U":
        base_score = round_up(min(impact + exploitability, 10.0))
    else:
        base_score = round_up(min(1.08 * (impact + exploitability), 10.0))

    vector = f"CVSS:3.1/AV:{av.upper()}/AC:{ac.upper()}/PR:{pr.upper()}/UI:{ui.upper()}/S:{scope}/C:{c.upper()}/I:{i.upper()}/A:{a.upper()}"
    return base_score, vector

def score_to_severity(score: float) -> str:
    """Translates CVSS score into standard severity tier."""
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0.0:
        return "LOW"
    return "INFORMATIONAL"
